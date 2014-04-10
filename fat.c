#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>
#include <ctype.h>
#include "fat.h"
#include "fatstruct.h"
#include "fathelper.h"
#include "disk.h"
#include "utils.h"

#define NUM_HANDLES 4

typedef struct fat_filehandle
{
	int file_sector; //disk sector file entry is in
	int file_offset; //number of the file entry within the sector
	unsigned int fp; // location of the file pointer (bytes from start of file)
	char mode; // 'r' for read, 'w' for write, 'a' for append
	bool open; // is the file handle in use?
	bool unlink; // should the file be unlinked when closed?
} fat_filehandle_t;

void print_directory_sector(int sector);

fat_filehandle_t file_handles[NUM_HANDLES];
uint8_t boot_sector[DISK_BLOCK_SIZE];
bool mounted = false;

int fat_mkfs(char* name, unsigned int size)
{
	struct_check();
	make_disk(name, size);
	open_disk(name);
	int disk_size_bytes = disk_size();
	int total_sectors = disk_size_bytes / DISK_BLOCK_SIZE;

	debug_printf("making boot sector\n");
	fat_bs_t bs_struct;
	char jump_bytes[3] = {0x00, 0x00, 0x00};
	memcpy(&bs_struct.jump, jump_bytes, sizeof(bs_struct.jump));
	char oem_label[] = "CSYS2014";
	memcpy(&bs_struct.oem, oem_label, sizeof(bs_struct.oem));
	bs_struct.bpb.bytes_sector = DISK_BLOCK_SIZE;
	//2MiB - 2GiB
	if(disk_size_bytes < MINIMUM_DISK_SIZE &&
		disk_size_bytes > MAXIMUM_DISK_SIZE)
	{
		debug_printf("invalid disk size");
		return -1;
	}
	int sectors_per_cluster = 1;
	if(disk_size_bytes > 1<<22) //4MiB
		sectors_per_cluster = 2;
	if(disk_size_bytes > 1<<24) //16MiB
		sectors_per_cluster = 4;
	bs_struct.bpb.sectors_cluster = (uint8_t)sectors_per_cluster;
	int reserved_sectors = 1; //just the boot sector
	bs_struct.bpb.reserved_sectors = (uint16_t)reserved_sectors;
	bs_struct.bpb.fats = 2;
	bs_struct.bpb.root_entries = 512;
	if(total_sectors > 65535)
		bs_struct.bpb.sectors_volume = 0;
	else
		bs_struct.bpb.sectors_volume = (uint16_t)total_sectors;
	bs_struct.bpb.mdt = 0xf8;
	int non_reserved_sectors = total_sectors - reserved_sectors;
	//integer division, round up
	int non_reserved_clusters =
	(non_reserved_sectors + sectors_per_cluster - 1) / sectors_per_cluster;
	int entries_per_fat_sector = DISK_BLOCK_SIZE / sizeof(uint16_t);
	//again, integer division, round up
	bs_struct.bpb.sectors_fat =
	(uint16_t)((non_reserved_clusters + entries_per_fat_sector - 1) /
		entries_per_fat_sector);
	bs_struct.bpb.sectors_track = 0;
	bs_struct.bpb.heads = 0;
	bs_struct.bpb.hidden_sectors = 0;
	if(total_sectors > 65535)
		bs_struct.bpb.huge_sectors_volume = (uint32_t)total_sectors;
	else
		bs_struct.bpb.huge_sectors_volume = 0;
	bs_struct.ebpb.drive_num = 0;
	bs_struct.ebpb.nt_flags = 0;
	bs_struct.ebpb.signature = 0x29;
	bs_struct.ebpb.volume_id = 0x1234abcd;
	char vol_label[] = "VOL LABEL  ";
	memcpy(&bs_struct.ebpb.volume_label, &vol_label,
		sizeof(bs_struct.ebpb.volume_label));
	char fat_type[] = "FAT16   ";
	memcpy(&bs_struct.ebpb.fat_type_label, &fat_type,
		sizeof(bs_struct.ebpb.volume_label));
	bzero(&bs_struct.boot, sizeof(bs_struct.boot));
	uint8_t boot_sig[2] = {0x55, 0xaa};
	memcpy(&bs_struct.signature, &boot_sig, 2);
	uint8_t boot_sect[DISK_BLOCK_SIZE];
	memcpy(&boot_sect, &bs_struct, DISK_BLOCK_SIZE);
	write_block(0, &boot_sect);
	debug_printf("boot sector written\n");

	/* file allocation table */
	debug_printf("making FAT\n");
	int fat_entries =
	((int)bs_struct.bpb.sectors_fat * (int)bs_struct.bpb.bytes_sector) /
	(int)sizeof(uint16_t);
	uint16_t fat[fat_entries];
	fat[0] = (uint16_t)(0xff + (bs_struct.bpb.mdt << 8));
	fat[1] = 0xffff;
	for(int i = 2; i < fat_entries; ++i)
	{
		fat[i] = 0x0000;
	}
	uint8_t fat_bytes[bs_struct.bpb.bytes_sector * bs_struct.bpb.sectors_fat];
	bzero(&fat_bytes, (size_t)(bs_struct.bpb.bytes_sector * bs_struct.bpb.sectors_fat));
	memcpy(&fat_bytes, &fat, (size_t)fat_entries * sizeof(uint16_t));
	int fat1_start = bs_struct.bpb.reserved_sectors;
	int fat2_start = fat1_start + bs_struct.bpb.sectors_fat;
	for(int i = 0; i < bs_struct.bpb.sectors_fat; ++i)
	{
		//write the first and second FAT in one go - they're identical
		write_block(fat1_start + i, &fat_bytes[i * bs_struct.bpb.bytes_sector]);
		write_block(fat2_start + i,	&fat_bytes[i * bs_struct.bpb.bytes_sector]);
	}
	debug_printf("FATs written\n");

	/* root directory */
	debug_printf("making root directory\n");
	int root_dir_size = bs_struct.bpb.root_entries * (int)sizeof(fat_file_t);
	uint8_t root_dir_bytes[root_dir_size];
	//zeroing the whole thing will make the first byte of the filename field zero
	//indicating no files exist
	bzero(&root_dir_bytes, (size_t)root_dir_size);
	int root_dir_start = bs_struct.bpb.reserved_sectors +
	bs_struct.bpb.fats * bs_struct.bpb.sectors_fat;
	//integer division, round up
	int root_sectors =
	(root_dir_size + bs_struct.bpb.bytes_sector - 1) / bs_struct.bpb.bytes_sector;
	for(int i = 0; i < root_sectors; ++i)
	{
		if(write_block(root_dir_start + i,
			&root_dir_bytes[i * bs_struct.bpb.bytes_sector]) < 0 )
		{
			return -1;
		}
	}
	debug_printf("root directory written\n");
	close_disk();
	return size;
}

void print_directory_sector(int sector)
{
	uint8_t dir_sector[bytes_sector()];
	read_block(sector, &dir_sector);
	fat_file_t dir_files[dir_entries_sector()];
	memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());
	for(int i = 0; i < dir_entries_sector(); ++i)
	{
		if(dir_files[i].name[0] == 0x00)
		{
			printf("file %d name starts with null byte", i);
			continue;
		}
		else if(dir_files[i].name[0] == deleted_file)
		{
			printf("file %d deleted\n", i);
			continue;
		}
		else if(is_lfn(dir_files[i].attr))
		{
			printf("file %d used for LFN\n", i);
			continue;
		}
		printf("%.8s.%.3s", dir_files[i].name, dir_files[i].ext);
		printf(" at cluster %x size %u", dir_files[i].first_cluster,
			dir_files[i].size);
		printf(" attr ");
		print_attributes(dir_files[i].attr);
		printf("\n");
	}
	return;
}

int fat_mount(char* disk_image)
{
	if(mounted)
	{
		debug_printf("already mounted\n");
		return -1;
	}
	//initialise filehandles
	for(int i = 0; i < NUM_HANDLES; ++i)
	{
		file_handles[i].open = false;
	}
	//read boot sector
	if(open_disk(disk_image) < 0)
	{
		debug_printf("unable to open disk\n");
		return -1;
	}
	if(read_block(0, &boot_sector) < 0)
	{
		debug_printf("unable to read boot sector\n");
		return -1;
	}
	//sanity check
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	if(bs_struct.signature[0] != 0x55 || bs_struct.signature[1] != 0xaa)
	{
		debug_printf("incorrect signature\n");
		close_disk();
		return -1;
	}
	char fat_type[] = "FAT16   ";
	if(memcmp(&bs_struct.ebpb.fat_type_label, &fat_type,
		sizeof(bs_struct.ebpb.fat_type_label)) != 0)
	{
		debug_printf("different FAT type to expected\n");
		close_disk();
		return -1;
	}
	if(bs_struct.bpb.bytes_sector != DISK_BLOCK_SIZE)
	{
		debug_printf("incorrect bytes per sector\n");
		close_disk();
		return -1;
	}
	print_bs();
	mounted = true;
	return 0;
}

int fat_umount()
{
	if(!mounted)
	{
		debug_printf("disk not mounted\n");
		return -1;
	}
	bzero(&boot_sector, (size_t)bytes_sector());
	for(int i = 0; i < NUM_HANDLES; ++i)
	{
		file_handles[i].open = false;
	}
	if(close_disk() < 0)
	{
		return -1;
	}
	mounted = false;
	return 0;
}

int fat_open(char *name, char mode)
{
	if(!mounted)
	{
		debug_printf("disk not mounted\n");
		return -1;
	}
	/* allow mode to be 'w' or 'a' as well */
	// if(mode != 'r')
	// {
	// 	debug_printf("invalid mode\n");
	// 	return -1;
	// }
	//find an unused handle
	int handle = -1;
	for(int i = 0; i < NUM_HANDLES; ++i)
	{
		if(file_handles[i].open == false)
		{
			handle = i;
			break;
		}
	}
	if(handle == -1)
	{
		debug_printf("all file handles in use\n");
		return -1;
	}

	// print out how many '/' in the path
	// int numOfSubd = 0;
	// for(int i=0;name[i]!='\0';i++)
	// {	
	// 	if(name[i]=='/')
	// 	{
	// 		numOfSubd++;
	// 		break;
	// 	}
	// }
	// printf("there is %d '/' in the string\n", numOfSubd);

	//traverse directories, find the file
	char namecopy1[MAX_PATH_LEN + 1];
	strncpy(namecopy1, name, MAX_PATH_LEN);
	namecopy1[MAX_PATH_LEN] = '\0';

	char namecopy2[MAX_PATH_LEN + 1];
	strncpy(namecopy2, name, MAX_PATH_LEN);
	namecopy2[MAX_PATH_LEN] = '\0';

	// set dname to direction name
	// and set bname to base name
	char* dname = dirname(namecopy1);
	char* bname = basename(namecopy2);

	debug_printf("directory name: %s\n", dname);
	debug_printf("file name: %s\n", bname);

	printf("directory name: %s\n", dname);
	printf("file name: %s\n", bname);

	//get the sector number of this directory
	int directory_sector = dir_lookup(dname);


	//start of real data 97 + offset 23(25-3) = 120
	
	if(directory_sector < 0)
	{
		debug_printf("directory does not exist");
		return -1;
	}

	//get the sector number of this file
	int file_entry_number = file_lookup(bname, &directory_sector);


	if(file_entry_number < 0 && mode == 'r')
	{
		//file needs to exist for read mode
		return -1;
	}
	if(file_entry_number < 0 && (mode =='w' || mode == 'a'))
	{
		/* need to create new file */
		// fopen(name, "W+"); /*create the new file*/
		dir_create(bname, directory_sector);
		// dir_create(bname, directory_sector);
		return 0;
	}
	
	printf("directory_sector: %d\n", directory_sector);
	printf("file_entry_number: %d\n", file_entry_number);

	//read the file structure
	fat_file_t f_entry;
	read_file_entry(&f_entry, directory_sector, file_entry_number);
	//truncate file if in write mode

	if(mode == 'w' && f_entry.size > 0)
	{
		/* existing file needs to be truncated in write mode */
		// make the whole block to 0
		int file_context = start_of_data() + f_entry.first_cluster - 2;
		int bytes_cluster = bytes_sector() * sectors_cluster();
		uint8_t cluster[bytes_cluster];
		for (int i; i< bytes_cluster ;i++)
		{
			cluster[i] = 0x00;
		}
		write_block(file_context,cluster);
		printf("Block %d is cleaned to 0x00 \n", file_context);

		return handle;
	}



	//set up file handle
	debug_printf("using file handle %d\n", handle);
	file_handles[handle].file_sector = directory_sector;
	file_handles[handle].file_offset = file_entry_number;
	if(mode == 'a')
	{
		/*initialise file pointer to end of file*/
		return handle;
	}
	else
	{
		file_handles[handle].fp = 0;
	}
	file_handles[handle].mode = mode;
	file_handles[handle].open = true;
	file_handles[handle].unlink = false;
	return handle;
}

int fat_close(int fd)
{
	if(!mounted)
	{
		debug_printf("disk not mounted\n");
		return -1;
	}
	if(fd < 0 && fd >= NUM_HANDLES)
	{
		debug_printf("invalid file descriptor");
		return -1;
	}
	if(!file_handles[fd].open)
	{
		debug_printf("file not open\n");
		return -1;
	}
	//usually flush() would get called here
	//but this implementation doesn't have any buffer/cache
	//don't need to do that
	fat_file_t f_entry;
	read_file_entry(&f_entry, file_handles[fd].file_sector,
		file_handles[fd].file_offset);
	file_handles[fd].open = false;
	if(file_handles[fd].unlink == true)
	{
		debug_printf("unlinking file on close\n");
		/* find first cluster of file */
		/* work along FAT chain, mark each cluster as free */
	}
	return 0;
}

int fat_read(int fd, void *buf, unsigned int count)
{
	if(!mounted)
	{
		debug_printf("not mounted\n");
		return -1;
	}
	if(fd < 0 || fd >= NUM_HANDLES)
	{
		debug_printf("invalid file handle\n");
		return -1;
	}
	if(!file_handles[fd].open)
	{
		debug_printf("file not open\n");
		return -1;
	}
	if(file_handles[fd].mode != 'r')
	{
		debug_printf("wrong file mode\n");
		return -1;
	}
	if(count == 0)
	{
		return 0;
	}
	int bytes_cluster = bytes_sector() * sectors_cluster();
	int read_start_cluster = (int)file_handles[fd].fp / bytes_cluster;
	fat_file_t f_entry;
	read_file_entry(&f_entry, file_handles[fd].file_sector,
		file_handles[fd].file_offset);
	if(file_handles[fd].fp >= f_entry.size)
	{
		return 0;
	}
	uint16_t current_cluster = f_entry.first_cluster;
	for(int i = 0; i < read_start_cluster; ++i)
	{
		int next_c = next_cluster(current_cluster);
		if(next_c <= max_cluster && next_c >= min_cluster)
		{
			current_cluster = (uint16_t)next_c;
		}
		else
		{
			//file length says it should have more clusters
			//but the FAT chain isn't long enough
			exit_error("invalid cluster reference in FAT");
		}
	}
	int offset_in_cluster = (int)file_handles[fd].fp % bytes_cluster;
	int bytes_read = 0;
	int bytes_to_read = (int)count;
	uint8_t *memptr = buf;
	int remaining_in_file = (int)f_entry.size - (int)file_handles[fd].fp;
	while(bytes_to_read > 0 && remaining_in_file > 0)
	{
		uint8_t cluster[bytes_cluster];
		int first_sector = data_cluster_to_sector(current_cluster);
		for(int i = 0; i < sectors_cluster(); ++i)
		{
			read_block(first_sector + i, &cluster[i * bytes_sector()]);
		}
		int remaining_in_cluster = bytes_cluster - offset_in_cluster;
		int readable = imin(bytes_to_read,
			imin(remaining_in_file, remaining_in_cluster));
		memcpy(memptr + bytes_read, &cluster[offset_in_cluster], (size_t)readable);
		bytes_read += readable;
		bytes_to_read -= readable;
		remaining_in_cluster -= readable;
		remaining_in_file -= readable;
		file_handles[fd].fp += (unsigned int)readable;
		if(bytes_to_read == 0 || remaining_in_file == 0)
		{
			break;
		}
		//read as much as possible from that cluster
		//update current_cluster to get the next one
		int next_c = next_cluster(current_cluster);
		if(next_c <= max_cluster && next_c >= min_cluster)
		{
			current_cluster = (uint16_t)next_c;
			offset_in_cluster = 0;
		}
		else
		{
			exit_error("invalid cluster reference in FAT");
		}
	}
	return bytes_read;
}

int fat_lseek(int fd, unsigned int offset, int whence)
{
	if(!mounted)
	{
		debug_printf("not mounted\n");
		return -1;
	}
	if(fd < 0 || fd >= NUM_HANDLES)
	{
		debug_printf("invalid file handle\n");
		return -1;
	}
	if(!file_handles[fd].open)
	{
		debug_printf("file not open\n");
		return -1;
	}
	if(!(whence == fat_SEEK_SET || whence == fat_SEEK_CUR || whence == fat_SEEK_END))
	{
		debug_printf("invalid whence\n");
		return -1;
	}
	fat_file_t f_entry;
	read_file_entry(&f_entry, file_handles[fd].file_sector,
		file_handles[fd].file_offset);
	int file_size = f_entry.size;
	int new_fp = 0;
	if(whence == fat_SEEK_SET)
	{
		new_fp = offset;
	}
	else if(whence == fat_SEEK_CUR)
	{
		new_fp = file_handles[fd].fp + offset;
	}
	else if(whence == fat_SEEK_END)
	{
		new_fp = file_size + offset;
	}
	if(new_fp > file_size)
	{
		if(file_handles[fd].mode == 'r')
		{
			debug_printf("tried to seek off end of file\n");
			return -1;
		}
		//extend the file so that the file pointer is at the end of file
		uint8_t zeros[bytes_sector()];
		bzero(&zeros, (size_t)bytes_sector());
		int extension_needed = new_fp - file_size;
		while(extension_needed > 0)
		{
			int this_write = bytes_sector();
			if(extension_needed < bytes_sector())
			{
				this_write = extension_needed;
			}
			fat_write(fd, &zeros, this_write);
			extension_needed -= this_write;
		}
	}
	//update the actual file pointer
	file_handles[fd].fp = new_fp;
	return (int)file_handles[fd].fp;
}
/** Write from an already opened file

@param fd File descriptor
@param buf Buffer for file contents to come from
@param count Maximum number of bytes to write
@return Number of bytes written to file or -1 for error
*/
int fat_write(int fd, void *buf, unsigned int count)
{
	(void)fd;
	(void)buf;
	(void)count;
	/* check input arguments for errors */
	if(!mounted)
	{
		debug_printf("not mounted\n");
		return -1;
	}
	if(fd < 0 || fd >= NUM_HANDLES)
	{
		debug_printf("invalid file handle\n");
		return -1;
	}
	if(!file_handles[fd].open)
	{
		debug_printf("file not open\n");
		return -1;
	}
	// if(file_handles[fd].mode != 'r')
	// {
	// 	debug_printf("wrong file mode\n");
	// 	return -1;
	// }
	if(count == 0)
	{
		return 0;
	}
	file_handles[fd]








	
	// printf("		this is the fd %d  \n",fd);



	/* locate the first cluster of the file */
	/* handle situation where file size is zero and no cluster has been
	allocated - allocate the first cluster */
	/* calculate how many clusters into the file the filepointer is and follow
	FAT chain to reach current cluster*/
	/* calculate filepointer location in current cluster */
	/* while more data remains to write */
	/*{*/
		/* if there is any data before filepointer in current cluster, read it
		into memory*/

		/* calculate number of bytes that can be written into current cluster */
		/* copy bytes into cluster-sized memory buffer */
		/* write cluster to disk */
		/* update counters - bytes left to write, file size, file pointer */
		/* update timestamps */
		/* write timestamps and file size in file entry to disk */
		/* if cluster is full, find next cluster */
		/* allocate a new cluster if necessary */
	/*}*/
	return -1;
}

int fat_unlink(char *path)
{
	(void)path;
	/* check input arguments for errors */
	/* traverse directories, find the file and the directory it's in */
	/* check if there are any open file handles on the file */
	/* if there are, set the unlink-on-close flag */
	/* check that the "file" isn't actually a directory */
	/* work along FAT chain, mark each cluster as free */
	/* mark file entry as deleted, write entry to disk */
	return -1;
}

int fat_mkdir(char *path)
{
	(void)path;
	/* check input arguments for errors */
	/* traverse directories, find the parent directory it's in */
	/* check there isn't a file or directory with the same name already */
	/* create a new file, then set its directory bit to true */
	/* allocate a cluster for the directory */
	/* make a memory buffer for the directory cluster, fill with zeros */
	/* create the . and .. entries in the new directory */
	/* write directory cluster to disk */
	return -1;
}

int fat_rmdir(char *path)
{
	(void) path;
	/* check input arguments for errors */
	/* traverse directories, find the file and the directory it's in */
	if(!mounted)
	{
		debug_printf("disk not mounted\n");
		return -1;
	}
	int handle = -1;
	for(int i = 0; i < NUM_HANDLES; ++i)
	{
		if(file_handles[i].open == false)
		{
			handle = i;
			break;
		}
	}
	if(handle == -1)
	{
		debug_printf("all file handles in use\n");
		return -1;
	}
	/* check the directory to be removed isn't the root directory */
	/* check the directory doesn't contain any files */
	/* work along FAT chain, mark each cluster as free */
	/* mark file entry as deleted, write entry to disk */
	return -1;
}

// //returns the location of new created directory, negative = er
// int dir_create(char* bname, int directory_sector)
// {
// 	(void) bname;
// 	//check wehter the block is already full
// 	bool full_flag = true;
// 	int start_of_data = start_of_root_dir() + root_dir_sectors();
// 	int start_of_fat_data = start_of_fat();


// 	int fat_entries_sector = bytes_sector() / (int)sizeof(uint16_t);
// 	uint8_t fat_bytes[bytes_sector()];
// 	read_block(start_of_fat(), &fat_bytes);
// 	uint16_t fat_entries[fat_entries_sector];

// 	memcpy(&fat_entries, &fat_bytes, (size_t)bytes_sector());

// 	//read sector into a memory block
// 	uint8_t dir_sector[bytes_sector()];
// 	read_block(directory_sector, &dir_sector);
// 	fat_file_t dir_files[dir_entries_sector()];

// 	char* fname;
// 	char* fext;
// 	int i;

// 	memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());

// 	for(i = 0; i < dir_entries_sector(); ++i)
// 	{
// 		// printf("!!!dir_files[i].name[0] %d \n" , dir_files[i].name[0]);
// 		// find an empty entry
// 		if (dir_files[i].name[0] == 0x00)
// 		{
// 			//find an empty entry in fat
// 			for(int j = 0; j < fat_entries_sector; ++j)
// 			{
// 				if ( fat_entries[j] == 0x0000)
// 				{

// 					printf("@@@the firss empty fat_entreies %d \n", i);
// 					//assume one block is enough for the new data
// 					// fat_entries[i] == 0xffff;
// 					fat_file_t file[dir_entries_sector()];


// 					name_to_83(bname,&fname, &fext);
// 					printf("@@@ name; = %s \n",&fname);	
// 					printf("@@@ ext; = %s \n",&fext);

// 					memcpy(dir_files[i].name,&fname,FAT_FILE_LEN);
// 					memcpy(dir_files[i].ext,&fext,FAT_EXT_LEN);
// 					dir_files[i].first_cluster = (uint16_t)j;

// 					write_file_entry(dir_files[i],directory_sector,i);
// 					printf(" shit, hey I'm here == %d \n", (uint16_t)j);

// 					full_flag = false;
// 					break;			
// 				}
// 			}
// 			break;
// 		}
// 	}
// 	//if the block is already full create a new one
// 	if(full_flag){
// 		// create a new block
// 		// set fat to this block
// 		// create a entry inside this block
// 		for(int j = 0; j < fat_entries_sector; ++j)
// 		{
// 			if ( fat_entries[j] == 0x0000)
// 			{
// 				dir_files[i]
// 				//set the fat to new block
// 				fat_entries[int(fat_entries[i].first_cluster)] = j;
// 				fat_entries[j] = 0xffff;
// 				directory_sector = start_of_data + j;
// 			}
// 		}
// 	}
// 	return start_of_data + i;
// }
int dir_create(char* bname, int directory_sector)
{


	(void) bname;
	(void) directory_sector;




	if(check_block(directory_sector))
	{

		file_create(bname, directory_sector);
	}
	else// handles for the situation that the block is already full
	{
		printf(" The block is full \n");


		// int old_block = directory_sector - start_of_data;
		// int new_block;
		// int new_directory_sector;

		// // there is only one block used to store the dir, and it's full
		// if (fat_entries[old_block] == free_cluster)
		// {
		// 	//find an empty entry in fat
		// 	for(new_block = 0; new_block < fat_entries_sector; ++new_block)
		// 	{
		// 		if ( fat_entries[new_block] == free_cluster)
		// 		{
		// 			write_fat_entry((uint16_t)old_block,(uint16_t)new_block);
		// 			break;
		// 		}
		// 	}
		// 	new_directory_sector = new_block + start_of_data;

		// 	read_block(new_directory_sector, &dir_sector);
		// 	memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());

		// }
	}
		// int new block
	// printf(" *******old_block %d \n", old_block);
	return 0;

}
int file_create(char* bname, int directory_sector)
{
	int fat_entries_sector = bytes_sector() / (int)sizeof(uint16_t);
	uint8_t fat_bytes[bytes_sector()];
	read_block(start_of_fat(), &fat_bytes);
	uint16_t fat_entries[fat_entries_sector];
	memcpy(&fat_entries, &fat_bytes, (size_t)bytes_sector());

	int start_of_data = start_of_root_dir() + root_dir_sectors();
	int start_of_fat_data = start_of_fat();
	//read sector into a memory block
	uint8_t dir_sector[bytes_sector()];
	read_block(directory_sector, &dir_sector);
	fat_file_t dir_files[dir_entries_sector()];
	memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());

	char* fname; // file name
	char* fext;  // extension name
	int i;
	name_to_83(bname,&fname, &fext);
	
	printf("fat_entries[34]  %d \n", fat_entries[34]);

	for(i = 0; i < dir_entries_sector(); ++i)
	{
			// printf("!!!dir_files[i].name[0] %d \n" , dir_files[i].name[0]);
			// find an empty entry
		if (dir_files[i].name[0] == 0x00)
		{
				//find an empty entry in fat
			for(int j = 0; j < fat_entries_sector; ++j)
			{
				if ( fat_entries[j] == free_cluster)
				{
					printf("@@@the first empty entreies %d \n", j);

					memcpy(dir_files[i].name,&fname,FAT_FILE_LEN);
					memcpy(dir_files[i].ext,&fext,FAT_EXT_LEN);
					dir_files[i].first_cluster = (uint16_t)j;

					write_file_entry(dir_files[i],directory_sector,i);
						// assume one block is enough for the new data
					write_fat_entry((uint16_t)j,(uint16_t)0xffff);;
					printf(" empty block == %d \n", (uint16_t)j);
					break;
				}
			}
			break;
		}
	}
	return 0;
}
//check weather there is spare room for an entry
int check_block(int directory_sector)
{

	int start_of_data = start_of_root_dir() + root_dir_sectors();
	int start_of_fat_data = start_of_fat();
	//read sector into a memory block
	uint8_t dir_sector[bytes_sector()];
	read_block(directory_sector, &dir_sector);
	fat_file_t dir_files[dir_entries_sector()];
	memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());

	for(int i = 0; i < dir_entries_sector(); ++i)
	{
		// printf("!!!dir_files[i].name[0] %d \n" , dir_files[i].name[0]);
		// find an empty entry
		// printf("--->%d\n",dir_files[i].name[0]);
		if (dir_files[i].name[0] == 0x00)
		{
			return true;
		}
	}
	return false;
}
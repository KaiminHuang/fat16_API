#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "utils.h"
#include "fatstruct.h"
#include "fathelper.h"
#include "disk.h"

extern uint8_t boot_sector[DISK_BLOCK_SIZE];

void struct_check()
{
	//check structure sizes are correct
	assert(sizeof(fat_bpb_t) == 25);
	assert(sizeof(fat_ebpb_t) == 26);
	assert(sizeof(fat_bs_t) == DISK_BLOCK_SIZE);
	assert(sizeof(fat_file_t) == 32);
	assert(sizeof(fat_attr_t) == 1);
	assert(sizeof(fat_date_t) == 2);
	assert(sizeof(fat_time_t) == 2);
	//check that the machine is little endian
	int i = 1;
	assert((int)*((unsigned char *)&i)==1);
	//make sure int range is reasonable
	assert(sizeof(int) >= 4);
	return;
}

void print_bs()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	debug_printf("jump opcodes: %02x %02x %02x\n",
		bs_struct.jump[0], bs_struct.jump[1], bs_struct.jump[2]);
	debug_printf("oem name: %.8s\n", bs_struct.oem);
	debug_printf("bytes per sector: %u\n", bs_struct.bpb.bytes_sector);
	debug_printf("sectors per cluster: %u\n", bs_struct.bpb.sectors_cluster);
	debug_printf("reserved sectors: %u\n", bs_struct.bpb.reserved_sectors);
	debug_printf("number of FATs: %u\n", bs_struct.bpb.fats);
	debug_printf("root directory entries: %u\n", bs_struct.bpb.root_entries);
	debug_printf("sectors per volume: %u\n", bs_struct.bpb.sectors_volume);
	debug_printf("media descriptor: %02x\n", bs_struct.bpb.mdt);
	debug_printf("sectors per FAT: %u\n", bs_struct.bpb.sectors_fat);
	debug_printf("sectors per track: %u\n", bs_struct.bpb.sectors_track);
	debug_printf("heads: %u\n", bs_struct.bpb.heads);
	debug_printf("hidden sectors: %u\n", bs_struct.bpb.hidden_sectors);
	debug_printf("huge sectors per volume: %u\n", bs_struct.bpb.huge_sectors_volume);
	debug_printf("drive number: %u\n", bs_struct.ebpb.drive_num);
	debug_printf("windows nt flags: %u\n", bs_struct.ebpb.nt_flags);
	debug_printf("ebpb signature: %u\n", bs_struct.ebpb.signature);
	debug_printf("volume serial number: %u\n", bs_struct.ebpb.volume_id);
	debug_printf("volume label: %.11s\n", bs_struct.ebpb.volume_label);
	debug_printf("FAT type: %.8s\n", bs_struct.ebpb.fat_type_label);
	debug_printf("boot sector signature: %02x %02x\n",
		bs_struct.signature[0], bs_struct.signature[1]);
	return;
}

int number_of_fats()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.fats;
}

int bytes_sector()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	int b_s = bs_struct.bpb.bytes_sector;
	assert(b_s == DISK_BLOCK_SIZE);
	return b_s;
}

int sectors_cluster()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.sectors_cluster;
}

int sectors_fat()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.sectors_fat;
}

int start_of_fat()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.reserved_sectors;
}

int root_dir_entries()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.root_entries;
}

int start_of_root_dir()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return start_of_fat() + bs_struct.bpb.fats * bs_struct.bpb.sectors_fat;
}

int start_of_data()
{
	return start_of_root_dir() + root_dir_sectors();
}

int dir_entries_sector()
{
	// printf("~~~~~bytes_sector() = %d \n",bytes_sector());
	// printf("~~~~~(int)sizeof(fat_file_t)() = %d \n",(int)sizeof(fat_file_t));
	return bytes_sector() / (int)sizeof(fat_file_t);
}

int root_dir_sectors()
{
	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	return bs_struct.bpb.root_entries * (int)sizeof(fat_file_t) /
		bs_struct.bpb.bytes_sector;
}

int data_cluster_to_sector(uint16_t cluster)
{

	

	fat_bs_t bs_struct;
	memcpy(&bs_struct, &boot_sector, sizeof(boot_sector));
	// printf("		start_of_data() %d \n",start_of_data());
	// printf("		cluster %d \n",cluster);
	// printf("		FAT_CLUSTER_OFFSET %d \n",FAT_CLUSTER_OFFSET);
	// printf("		bs_struct.bpb.sectors_cluster %d \n",bs_struct.bpb.sectors_cluster);

	int sector = start_of_data() +
		(((int)cluster - FAT_CLUSTER_OFFSET) * bs_struct.bpb.sectors_cluster);
		
		
	return sector;
}

int sector_to_data_cluster(int sector)
{
	int data_sector = sector - start_of_data();
	int data_cluster = data_sector / sectors_cluster();
	return data_cluster + FAT_CLUSTER_OFFSET;
}

int highest_cluster()
{
	int disk_bytes = disk_size();
	int disk_sectors = disk_bytes / bytes_sector();
	int data_sectors = disk_sectors - start_of_data();
	int data_clusters = data_sectors / sectors_cluster();
	int total_clusters = FAT_CLUSTER_OFFSET + data_clusters;
	return total_clusters;
}

bool is_lfn(fat_attr_t attr)
{
	uint8_t attr_int;
	memcpy(&attr_int, &attr, sizeof(uint8_t));
	if(attr_int == 0x0f)
	{
		return true;
	}
	return false;
}

void print_attributes(fat_attr_t attr)
{
	uint8_t attr_int;
	memcpy(&attr_int, &attr, sizeof(uint8_t));
	char letters[] = "rhsvdadu";
	for(int i = 0; i < 8; ++i)
	{
		if(attr_int & (1<<i))
		{
			printf("%c", letters[i]);
		}
		else
		{
			printf("-");
		}
	}
	return;
}

fat_date_t date_now()
{
	fat_date_t d;
	time_t now;
	now = time(NULL);
	struct tm *now_tm = localtime(&now);
	d.day = now_tm->tm_mday;
	d.month = now_tm->tm_mon;
	d.year = now_tm->tm_year - 80;
	return d;
}

uint8_t fine_time_now()
{
	uint8_t t;
	time_t now;
	now = time(NULL);
	struct tm *now_tm = localtime(&now);
	t = (now_tm->tm_sec % 2) * 100;
	return t;
}

fat_time_t time_now()
{
	fat_time_t t;
	time_t now;
	now = time(NULL);
	struct tm *now_tm = localtime(&now);
	t.hour = now_tm->tm_hour;
	t.min = now_tm->tm_min;
	t.sec = now_tm->tm_sec / 2;
	return t;
}

uint16_t next_cluster(uint16_t current)
{
	int fat_start = start_of_fat();
	//FAT lookup
	int fat_offset = (int)current * (int)sizeof(uint16_t);
	int fat_sector = fat_start + (fat_offset / bytes_sector());
	int fat_entry_sector = current % (bytes_sector() / sizeof(uint16_t));
	uint16_t fat_piece[bytes_sector() / (int)sizeof(uint16_t)];
	read_block(fat_sector, &fat_piece);
	uint16_t fat_entry = fat_piece[fat_entry_sector];
	return fat_entry;
}

uint16_t next_cluster_for_sector(int current)
{
	int cluster = sector_to_data_cluster(current);
	uint16_t next_c = next_cluster((uint16_t)cluster);
	return next_c;
}

int chain_length(uint16_t start_cluster)
{
	uint16_t current = start_cluster;
	int length = 1;
	uint16_t next = next_cluster(current);
	while(next <= max_cluster && next >= min_cluster)
	{
		current = next;
		length++;
		next = next_cluster(current);
	}
	return length;
}

int write_fat_entry(uint16_t entry, uint16_t value)
{
	int fat_entries_sector = bytes_sector() / (int)sizeof(uint16_t);
	int sector = entry / fat_entries_sector;
	int entry_offset = (int)entry % fat_entries_sector;
	uint8_t fat_bytes[bytes_sector()];
	read_block(start_of_fat() + sector, &fat_bytes);
	uint16_t fat_entries[fat_entries_sector];
	memcpy(&fat_entries, &fat_bytes, (size_t)bytes_sector());
	fat_entries[entry_offset] = value;
	memcpy(&fat_bytes, &fat_entries, (size_t)bytes_sector());
	//multiple FATs
	for(int i = 0; i < number_of_fats(); ++i)
	{
		write_block(start_of_fat() + (i * sectors_fat()) + sector,
			&fat_bytes);
	}
	return 0;
}

int read_file_entry(fat_file_t* file, int directory_sector, int entry_number)
{
	uint8_t dir_bytes[bytes_sector()];
	read_block(directory_sector, &dir_bytes);
	fat_file_t dir_entries[dir_entries_sector()];
	memcpy(&dir_entries, &dir_bytes, (size_t)bytes_sector());
	*file = dir_entries[entry_number];
	return 0;
}

int write_file_entry(fat_file_t file, int directory_sector, int entry_number)
{
	uint8_t dir_bytes[bytes_sector()];
	read_block(directory_sector, &dir_bytes);
	fat_file_t dir_entries[dir_entries_sector()];
	memcpy(&dir_entries, &dir_bytes, (size_t)bytes_sector());
	dir_entries[entry_number] = file;
	memcpy(&dir_bytes, &dir_entries, (size_t)bytes_sector());
	write_block(directory_sector, &dir_bytes);
	return 0;
}

int name_to_83(char* whole_name, unsigned char* name, unsigned char* ext)
{
	//prefill with spaces
	for(int i = 0; i < FAT_FILE_LEN; ++i)
	{
		name[i] = ' ';
	}
	for(int i = 0; i < FAT_EXT_LEN; ++i)
	{
		ext[i] = ' ';
	}
	bool name_part = true;
	int name_ctr = 0;
	int ext_ctr = 0;
	char current_dir[] = ".";
	if(strncmp(whole_name, current_dir, 11) == 0)
	{
		name[0] = '.';
		return 0;
	}
	char parent_dir[] = "..";
	if(strncmp(whole_name, parent_dir, 11) == 0)
	{
		name[0] = '.';
		name[1] = '.';
		return 0;
	}
	for(int i = 0; i < FAT_FILE_LEN + FAT_EXT_LEN + 1; ++i)
	{
		if(whole_name[i] == '\0')
		{
			break;
		}
		if(whole_name[i] == '.')
		{
			name_part = false;
		}
		else if(isupper(whole_name[i]) || isdigit(whole_name[i]))
		{
			if(name_part && name_ctr < FAT_FILE_LEN)
			{
				name[name_ctr] = (unsigned char)whole_name[i];
				name_ctr++;
			}
			else if(!name_part && ext_ctr < FAT_EXT_LEN)
			{
				ext[ext_ctr] = (unsigned char)whole_name[i];
				ext_ctr++;
			}
		}
	}
	if(name_ctr == 0)
	{
		return -1;
	}
	return 0;
}

int compare_filename(char* name, fat_file_t dir_entry)
{
	unsigned char name_name[FAT_FILE_LEN+1];
	unsigned char name_ext[FAT_EXT_LEN+1];
	name_name[FAT_FILE_LEN] = '\0';
	name_ext[FAT_EXT_LEN] = '\0';
	name_to_83(name, name_name, name_ext);
	for(int i = 0; i < FAT_FILE_LEN; ++i)
	{
		if(dir_entry.name[i] != name_name[i])
		{
			return 1;
		}
	}
	for(int i = 0; i < FAT_EXT_LEN; ++i)
	{
		if(dir_entry.ext[i] != name_ext[i])
		{
			return 1;
		}
	}
	return 0;
}

//returns sector number where directory is located, negative = error
int dir_lookup(char* path)
{
	char dname[MAX_PATH_LEN+1];
	dname[MAX_PATH_LEN] = '\0';
	strncpy(dname, path, MAX_PATH_LEN);
	char* dname_part = NULL;
	dname_part = strtok(dname, "/");
	int dlocation = start_of_root_dir();
	//special case for root directory
	char root_dir_dname[] = ".";
	if(strcmp(path, root_dir_dname) == 0)
	{
		return start_of_root_dir();
	}
	bool found = false;
	//traverse the directory structure
	while(dname_part != NULL)
	{
		found = false;
		debug_printf("looking for directory %s\n", dname_part);
		// printf("	====looking for directory %s\n", dname_part);
		// printf("	dir_entries_sector() = %d \n",dir_entries_sector());
		while(!found)
		{
			//read sector into a memory block
			uint8_t dir_sector[bytes_sector()];
			read_block(dlocation, &dir_sector);
			fat_file_t dir_files[dir_entries_sector()];
			

			memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());
			//search the memory block for matching name
			for(int i = 0; i < dir_entries_sector(); ++i)
			{
				if(dir_files[i].name[0] == 0x00)
				{
					//not found, don't need to keep looking
					// printf("	//not found, don't need to keep looking");

					break;
				}
				else if(dir_files[i].name[0] == deleted_file)
				{
					//deleted
					continue;
				}
				else if(is_lfn(dir_files[i].attr))
				{
					//LFN entry
					continue;
				}
				else if(dir_files[i].attr.vol == 1 ||
					dir_files[i].attr.dir == 0 ||
					dir_files[i].attr.device == 1)
				{
					//volume label, not a directory, device file
					continue;
				}
				if(compare_filename(dname_part, dir_files[i]) == 0)
				{
					//got a directory with the correct name
					dlocation = data_cluster_to_sector(dir_files[i].first_cluster);
					// printf("	dir_files[i].first_cluster: %d \n", dir_files[i].first_cluster);
					found = true;
					break;
				}
			}
			if(found)
			{
				break;
			}
			//directory not found yet, need to pick the next sector to search
			//(if available)
			if(dlocation < start_of_data())
			{
				if(dlocation < start_of_root_dir() + root_dir_sectors())
				{
					//there are more root directory sectors to search
					dlocation++;
				}
				else
				{
					//directory doesn't exist
					return -1;
				}
			}
			else
			{
				if((dlocation + 1 - start_of_data()) % sectors_cluster() != 0)
				{
					//more sectors in this cluster
					dlocation++;
				}
				else if(next_cluster_for_sector(dlocation) <= max_cluster)
				{
					//continues into another cluster
					uint16_t next_c = next_cluster_for_sector(dlocation);
					dlocation = data_cluster_to_sector(next_c);
				}
				else
				{
					//directory doesn't exist
					return -1;
				}
			}
		}
		// printf("	dlocation: %d \n", dlocation);

		dname_part = strtok(NULL, "/");
	}
	return dlocation;
}

//returns file entry number in directory or -1 for not found
int file_lookup(char* name, int *directory_sector)
{
	int dlocation = *directory_sector;
	bool root_dir = true;
	if(dlocation >= start_of_data())
	{
		root_dir = false;
	}
	debug_printf("looking for file %s\n", name);
	while(true)
	{
		uint8_t dir_sector[bytes_sector()];
		read_block(dlocation, &dir_sector);
		fat_file_t dir_files[dir_entries_sector()];
		memcpy(&dir_files, &dir_sector, (size_t)bytes_sector());
		//search the memory block for matching name
		for(int i = 0; i < dir_entries_sector(); ++i)
		{
			if(dir_files[i].name[0] == 0x00)
			{
				//not found, don't need to keep looking
				break;
			}
			else if(dir_files[i].name[0] == deleted_file)
			{
				//deleted
				continue;
			}
			else if(is_lfn(dir_files[i].attr))
			{
				//LFN entry
				continue;
			}
			else if(dir_files[i].attr.vol == 1 ||
				dir_files[i].attr.device == 1)
			{
				//volume label, device file
				continue;
			}
			if(compare_filename(name, dir_files[i]) == 0)
			{
				//got a directory with the correct name
				*directory_sector = dlocation;
				return i;
			}
		}
		//file not found yet, need to pick the next sector to search
		//if there is actually a next sector
		if(root_dir)
		{
			if(dlocation < start_of_root_dir() + root_dir_sectors())
			{
				//there are more root directory sectors to search
				dlocation++;
			}
			else
			{
				//file doesn't exist
				return -1;
			}
		}
		else
		{
			if((dlocation + 1 - start_of_data()) % sectors_cluster() != 0)
			{
				//more sectors to search in this cluster
				dlocation++;
			}
			else if(next_cluster_for_sector(dlocation) <= max_cluster)
			{
				//continues into another cluster
				uint16_t next_c = next_cluster_for_sector(dlocation);
				dlocation = data_cluster_to_sector(next_c);
			}
			else
			{
				return -1;
			}
		}
	}
	return -1;
}

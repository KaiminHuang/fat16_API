#ifndef FATHELPER_H
#define FATHELPER_H

#include <stdint.h>
#include <stdbool.h>
#include "fatstruct.h"

/** Checks structures have the expected byte sizes on the machine and compiler */
void struct_check(void);
/** Prints the FAT boot sector of the currently opened disk image */
void print_bs(void);
/** Number of FATs in the disk image */
int number_of_fats(void);
/** Bytes per sector */
int bytes_sector(void);
/** Sectors per cluster */
int sectors_cluster(void);
/** Sectors per FAT */
int sectors_fat(void);
/** Sector number where the first FAT starts */
int start_of_fat(void);
/** Number of root directory entries */
int root_dir_entries(void);
/** Sector number where the root directory starts */
int start_of_root_dir(void);
/** Sector number where the data area starts */
int start_of_data(void);
/** Number of fat_file_t entries that fit in a sector */
int dir_entries_sector(void);
/** Number of sectors occupied by the root directory */
int root_dir_sectors(void);
/** Converts a cluster number (in the data area) into a sector number */
int data_cluster_to_sector(uint16_t cluster);
/** Converts a sector number to a cluster number in the data area */
int sector_to_data_cluster(int sector);
/** Highest cluster number available on the disk */
int highest_cluster(void);
/** Checks if file attributes indicate the entry is used for a LFN */
bool is_lfn(fat_attr_t attr);
/** Prints a string representing file attributes */
void print_attributes(fat_attr_t attr);
/** Creates a date structure with the current local date */
fat_date_t date_now(void);
/** Hundredth of second level time counter */
uint8_t fine_time_now(void);
/** Creates a time structure with the current local time */
fat_time_t time_now(void);
/** Looks up the FAT to find the next cluster in the chain for a given cluster */
uint16_t next_cluster(uint16_t current);
/** Looks up the FAT to find the next cluster in the chain for a given sector */
uint16_t next_cluster_for_sector(int current);
/** Counts the length of a FAT chain in sectors */
int chain_length(uint16_t start_cluster);
/** Writes a single entry to all FATs on disk

@param entry The FAT entry number to be written (0-based)
@param value The value to write
@return 0 for success, -1 for failure
*/
int write_fat_entry(uint16_t entry, uint16_t value);
/** Reads a single file entry from a directory

@param file Pointer for file entry to be placed at
@param directory_sector Disk sector number containing the directory
@param entry_number Entry number within the sector (0-based)
@return 0 for success, -1 for failure
*/
int read_file_entry(fat_file_t* file, int directory_sector, int entry_number);

/** Writes a single file entry in a directory

@param file File entry to be written
@param directory_sector Disk sector number containing the directory
@param entry_number Entry number within the sector (0-based)
@return 0 for success, -1 for failure
*/
int write_file_entry(fat_file_t file, int directory_sector, int entry_number);
/** Converts a filename string to 8.3 format

@param whole_name Filename in C string format, null byte terminated
@param name 8 character long filename, padded with spaces, not null terminated
@param ext 8 character long extension, padded with spaces, not null terminated
@return 0 for success, -1 for failure
*/
int name_to_83(char* whole_name, unsigned char* name, unsigned char* ext);
/** Compares the filename of a file entry with a string

@param name Filename in C string format, null byte terminated
@param dir_entry File entry from a directory
@return 1 if names are different, 0 if names are the same
*/
int compare_filename(char* name, fat_file_t dir_entry);
/** Finds the directory associated with a file path

@param path Full file path, including file name using Unix style forward slashes as separator
@return Sector number where directory is located (first cluster) or negative value for error
*/
int dir_lookup(char* path);
/** Finds the file entry associated with a file path

@param name Full file path, including file name using Unix style forward slashes as separator
@param directory_sector Pointer to first sector of directory, may be modified if
	file is in a later linked cluster
@return File entry number in directory or negative value for error
*/
int file_lookup(char* name, int *directory_sector);

#endif //FATHELPER_H

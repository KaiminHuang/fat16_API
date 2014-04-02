#ifndef FATSTRUCT_H
#define FATSTRUCT_H

#include <stdint.h>
#include <stdbool.h>

#define FAT_FILE_LEN 8
#define FAT_EXT_LEN 3
#define FAT_CLUSTER_OFFSET 2
#define MAX_PATH_LEN 256

typedef struct fat_bpb
{
	uint16_t bytes_sector; // bytes per sector
	uint8_t sectors_cluster; // sectors per cluster
	uint16_t reserved_sectors; // reserved sectors
	uint8_t fats; // number of FATs
	uint16_t root_entries; // root directory entries
	uint16_t sectors_volume; // sectors in volume
	uint8_t mdt; // media descriptor type
	uint16_t sectors_fat; // sectors per FAT
	uint16_t sectors_track; // sectors per track
	uint16_t heads; // number of disk heads
	uint32_t hidden_sectors; // number of hidden sectors
	uint32_t huge_sectors_volume; // huge sectors in volume
}__attribute__((packed)) fat_bpb_t;

typedef struct fat_ebpb
{
	uint8_t drive_num; // drive number
	uint8_t nt_flags; // windows nt reserved flags
	uint8_t signature; // signature
	uint32_t volume_id; // volume id serial number
	unsigned char volume_label[FAT_FILE_LEN + FAT_EXT_LEN]; // volume label string
	unsigned char fat_type_label[FAT_FILE_LEN]; // fat label
}__attribute__((packed)) fat_ebpb_t;

typedef struct fat_bs
{
	uint8_t jump[3]; // boot jump code
	unsigned char oem[FAT_FILE_LEN]; // OEM name
	fat_bpb_t bpb; // BIOS parameter block
	fat_ebpb_t ebpb; // extended BIOS parameter block
	uint8_t boot[448]; // boot sector code
	uint8_t signature[2]; // boot sector signature
}__attribute__((packed)) fat_bs_t;

typedef struct fat_attr
{
	uint8_t read_only:1; // file is read only
	uint8_t hidden:1; // file is hidden in default directory listing
	uint8_t system:1; // file is a system file
	uint8_t vol:1; //volume label
	uint8_t dir:1; //directory
	uint8_t archive:1; // file should be backed up
	uint8_t device:1; // file is a device file
	uint8_t unused:1; // reserved, do not use
}__attribute__ ((packed)) fat_attr_t;

typedef struct fat_date
{
	uint8_t day:5; // day of month (1-31)
	uint8_t month:4; // month (1-12)
	uint8_t year:7; // year (1980 -> 0, 1981 -> 1 ... 2014 -> 34  and so on)
}__attribute__ ((packed)) fat_date_t;

typedef struct fat_time
{
	uint8_t sec:5; // seconds divided by 2 (0-29 generally, but 30 for leap second)
	uint8_t min:6; // minutes (0-59)
	uint8_t hour:5; // hours (0-23)
}__attribute__ ((packed)) fat_time_t;

typedef struct fat_file
{
	unsigned char name[FAT_FILE_LEN]; // name
	unsigned char ext[FAT_EXT_LEN]; // extension
	fat_attr_t attr; // attributes
	uint8_t nt_flags; // windows nt reserved flags
	uint8_t create_time_fine; // creation time (10ms units, 0-199)
	fat_time_t create_time; // creation time
	fat_date_t create_date; // creation date
	uint16_t reserved; // reserved, do not use
	uint16_t fat32_cluster; // high bits of first cluster for FAT32 (ignored by FAT16)
	fat_time_t lm_time; // last modified time
	fat_date_t lm_date; // last modified date
	uint16_t first_cluster; // low bits of first cluster
	uint32_t size; // file size
}__attribute__((packed)) fat_file_t;

/* FAT special values */

static const unsigned char deleted_file = 0xe5;

static const uint16_t free_cluster = 0x0000; // cluster not allocated to file/directory
static const uint16_t min_cluster = 0x0002; // the first usable FAT entry
// (the first two fat entries are special values)
static const uint16_t max_cluster = 0xFFEF; //maximum cluster value in FAT
static const uint16_t reserved_dnu = 0xFFF6; //reserved, do not use
static const uint16_t bad_sector = 0xFFF7; //bad disk sector
static const uint16_t last_cluster = 0xFFFF; //last cluster in a file/directory

#endif //FATSTRUCT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "utils.h"
#include "disk.h"

FILE *disk_image = NULL;
int disk_image_size = 0;

int file_size(FILE *fp);

int make_disk(char *name, unsigned int size)
{
	if(size < MINIMUM_DISK_SIZE || size > MAXIMUM_DISK_SIZE)
	{
		return -1;
	}
	FILE *fp = fopen(name, "wb");
	assert(fp != NULL);
	char blank_block[DISK_BLOCK_SIZE];
	memset(&blank_block, 0xe5, DISK_BLOCK_SIZE);
	int total_written = 0;
	while(total_written < (int)size)
	{
		size_t written = 0;
		written = fwrite(&blank_block, sizeof(char), DISK_BLOCK_SIZE, fp);
		assert(written == DISK_BLOCK_SIZE);
		total_written += (int)written;
	}
	fclose(fp);
	return total_written;
}

int open_disk(char *name)
{
	disk_image = fopen(name, "rb+");
	disk_image_size = file_size(disk_image);
	if(disk_image_size % DISK_BLOCK_SIZE != 0)
	{
		return -1;
	}
	if(disk_image_size < MINIMUM_DISK_SIZE || disk_image_size > MAXIMUM_DISK_SIZE)
	{
		return -1;
	}
	debug_printf("opened disk image %s\n", name);
	return disk_image_size;
}

int close_disk()
{
	if(disk_image == NULL)
	{
		return -1;
	}
	fclose(disk_image);
	disk_image = NULL;
	debug_printf("closed disk image\n");
	return 0;
}

int read_block(int block, void *buf)
{
	assert(disk_image != NULL);
	long offset = block * DISK_BLOCK_SIZE;
	assert(offset + DISK_BLOCK_SIZE < disk_image_size && offset >= 0);
	if(fseek(disk_image, offset, SEEK_SET) != 0)
	{
		return -1;
	}
	debug_printf("reading from block %u, offset %x\n", block, offset);
	uint8_t disk_block[DISK_BLOCK_SIZE];
	size_t rval = fread(&disk_block, sizeof(uint8_t), DISK_BLOCK_SIZE, disk_image);
	assert(rval == DISK_BLOCK_SIZE);
	memcpy(buf, &disk_block, DISK_BLOCK_SIZE);
	return DISK_BLOCK_SIZE;
}

int write_block(int block, const void *buf)
{
	assert(disk_image != NULL);
	long offset = block * DISK_BLOCK_SIZE;
	assert(offset + DISK_BLOCK_SIZE < disk_image_size && offset >= 0);
	int rval = fseek(disk_image, offset, SEEK_SET);
	assert(rval != -1);
	debug_printf("writing to block %u, offset %x\n", block, offset);
	uint8_t disk_block[DISK_BLOCK_SIZE];
	memcpy(&disk_block, buf, DISK_BLOCK_SIZE);
	size_t rval2 = fwrite(&disk_block, sizeof(uint8_t), DISK_BLOCK_SIZE, disk_image);
	assert(rval2 == DISK_BLOCK_SIZE);
	fflush(disk_image);
	return DISK_BLOCK_SIZE;
}

int disk_size()
{
	return disk_image_size;
}

int file_size(FILE *fp)
{
	assert(fp != NULL);
	//save original location
	long original_pos = ftell(fp);
	assert(original_pos != -1);
	//seek to end of file
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	assert(size != -1);
	//seek back to original location
	fseek(fp, original_pos, SEEK_SET);
	return (int)size;
}

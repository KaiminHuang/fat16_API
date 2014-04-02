#ifndef DISK_H
#define DISK_H

#define DISK_BLOCK_SIZE 512
#define MINIMUM_DISK_SIZE (2 << 21)
#define MAXIMUM_DISK_SIZE (2 << 25)

/** Creates a new disk image file

@param name File name
@param size Size in bytes
@return Size of the disk image file or -1 for error
*/
int make_disk(char *name, unsigned int size);
/** Open a disk image file

@param name File name
@return Size of the disk image file or -1 for error
*/
int open_disk(char *name);
/** Close disk image file

@return 0 for success or -1 for error
*/
int close_disk(void);
/** Write a block to disk image file

The block must be of size DISK_BLOCK_SIZE
@param block Disk block number
@param buf Pointer to buffer containing data to be written
@return Number of bytes written or -1 for error
*/
int write_block(int block, const void *buf);
/** Read a block from disk image file

The block must be of size DISK_BLOCK_SIZE
@param block Disk block number
@param buf Pointer to buffer data will be placed in
@return Number of bytes read or -1 for error
*/
int read_block(int block, void *buf);
/** Size of the currently open disk image

@return Size in bytes
*/
int disk_size(void);

#endif

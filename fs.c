#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>
#include "fat.h"
#include "utils.h"

int main(int argc, char **argv)
{
	(void)argv;
	if(argc > 1)
	{
		debug_printing = true;
	}
	else
	{
		debug_printing = false;
	}
	fat_mount("../Img/fat4m.img");
	unsigned char buf[512];
	// int file = fat_open("NOTES/WEEK2/WEEK2.TXT", 'r');
	int file_r = fat_open("NOTES/WEEK2/WEEK2.TXT", 'r');
	int file_w = fat_open("NOTES/WEEK4/WEEK4.TXT", 'w');

	int rval = fat_read(file_r, &buf, 500);


	// int wval = fat_write(file, &buf, 500);

	printf("=================\n");
	printf("read %d bytes\n", rval);
	printf("%s", buf);
	fat_close(file_r);
	fat_umount();
	return EXIT_SUCCESS;
}

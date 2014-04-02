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
	fat_mount("new.img");
	unsigned char buf[512];
	int file = fat_open("SUBDIR/SMALL.TXT", 'r');
	int rval = fat_read(file, &buf, 500);
	printf("read %d bytes\n", rval);
	printf("%s", buf);
	fat_close(file);
	fat_umount();
	return EXIT_SUCCESS;
}

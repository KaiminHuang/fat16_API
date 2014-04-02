#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

#include "utils.h"

bool debug_printing;

void exit_error(const char* msg)
{
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
}

void* malloc_wrapper(size_t size)
{
	assert(size != 0);
	void* temp = malloc(size);
	assert(temp != NULL);
	return temp;
}

void free_wrapper(void* ptr)
{
	assert(ptr != NULL);
	free(ptr);
	return;
}

int debug_printf(const char* restrict format, ...)
{
	if(!debug_printing)
		return 0;
	fprintf(stderr, "DEBUG: ");
	va_list args;
	va_start(args, format);
	int temp = vfprintf(stderr, format, args);
	va_end(args);
	return temp;
}

void print_hex(const void* ptr, unsigned int size)
{
	for(unsigned int i = 0; i < size; ++i)
	{
		const unsigned char* c_ptr = (const unsigned char*)ptr;
		if(i > 0 && i % 16 == 0)
		{
			printf("\n");
		}
		printf("%02x ", c_ptr[i]);
	}
	printf("\n");
	return;
}

int imin(int a, int b)
{
	if(a < b)
	{
		return a;
	}
	return b;
}

unsigned int umin(unsigned int a, unsigned int b)
{
	if(a < b)
	{
		return a;
	}
	return b;
}

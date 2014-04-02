#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

extern bool debug_printing;

/** Prints an error message, then exits */
void exit_error(const char* msg);
/** Wrapper for malloc() to check for NULL and easier hooking */
void* malloc_wrapper(size_t size);
/** Wrapper for free() to check for NULL and easier hooking */
void free_wrapper(void* ptr);
/** Disable-able print statement for debugging */
int debug_printf(const char* restrict format, ...);
/** Prints a hex-dump of a memory block */
void print_hex(const void* ptr, unsigned int size);
/** Minimum of two integers */
int imin(int a, int b);
/** Minimum of two unsigned integers */
unsigned int umin(unsigned int a, unsigned int b);

#endif //UTILS_H

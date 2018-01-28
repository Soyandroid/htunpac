#ifndef UTIL_MEM_H
#define UTIL_MEM_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Allocate memory on the heap and init it with 0 (calloc wrapper)
 *
 * @param nbytes Number of bytes to allocate
 * @return Pointer to allocated memory
 */
void* util_xcalloc(size_t nbytes);

/**
 * Allocate memory on the heap (malloc wrapper)
 *
 * @param nbytes Number of bytes to allocate
 * @return Pointer to allocated memory
 */
void* util_xmalloc(size_t nbytes);

/**
 * Realloc memory (realloc wrapper)
 *
 * @param mem Pointer to allocated memory to realloc/expand
 * @param nbytes New size of memory region
 * @return Pointer to reallocated memory region
 */
void* util_xrealloc(void* mem, size_t nbytes);

#endif

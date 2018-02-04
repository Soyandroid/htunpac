#define LOG_MODULE "util-mem"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#define LOG_MODULE "util-mem"

#include <stdint.h>

#include "mem.h"

void* util_xcalloc(size_t nbytes)
{
    void* mem;

    mem = calloc(nbytes, 1);

    if (mem == NULL) {
        log_die("xmalloc(%u) failed", (uint32_t) nbytes);
        return NULL;
    }

    return mem;
}

void* util_xmalloc(size_t nbytes)
{
    void* mem;

    mem = malloc(nbytes);

    if (mem == NULL) {
        log_die("xcalloc(%u) failed", (uint32_t) nbytes);
        return NULL;
    }

    return mem;
}

void* util_xrealloc(void* mem, size_t nbytes)
{
    void* newmem;

    newmem = realloc(mem, nbytes);

    if (newmem == NULL) {
        log_die("xrealloc(%p, %u) failed", mem, (uint32_t) nbytes);
        return NULL;
    }

    return newmem;
}
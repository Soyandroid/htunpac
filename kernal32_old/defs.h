#ifndef UTIL_DEFS_H
#define UTIL_DEFS_H

#include <stdint.h>

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#define XSTRINGIFY(arg) STRINGIFY(arg)

#define lengthof(x) (sizeof(x) / sizeof(x[0]))

#define containerof(ptr, outer_t, member) \
        ((void *) (((uint8_t *) ptr) - offsetof(outer_t, member)))

#endif

#ifndef KERNAL32_IAT_H
#define KERNAL32_IAT_H

#include <stdint.h>

#include "util/list.h"

struct iat_info_entry {
    struct list_node head;
    uint32_t addr;
    const char* name_dll;
    
    uint16_t num_imports;
    /* 64k imports should be fine to avoid dynamic allocation */
    struct import* imports[0xFFFF];
};

void iat_find_iats();

struct list* iat_get_found_iats();

void iat_log();

#endif
#ifndef KERNAL32_IMPORT_CACHE_H
#define KERNAL32_IMPORT_CACHE_H

#include <stdint.h>
#include <windows.h>

struct import {
    HMODULE module;
    const char* name;
    uint16_t ordinal;
};

const char* import_cache_get_dll_name(HMODULE module);

struct import* import_cache_get_import(uint32_t addr);

void import_cache_add_dll(HMODULE module, const char* name);

void import_cache_add_import_by_name(HMODULE module, void* addr, 
    const char* name);

void import_cache_add_import_by_ordinal(HMODULE module, void* addr, 
    uint16_t ordinal);

void import_cache_log();

void import_cache_dump_dll_to_file(const char* dll_name, const char* path);

#endif
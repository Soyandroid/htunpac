#ifndef KERNAL32_EXE_H
#define KERNAL32_EXE_H

#include <stdint.h>
#include <windows.h>

#include "kernal32/iat.h"

void exe_init(HMODULE module);

uint32_t exe_get_section_count();

void* exe_allocate_section(const char* name, uint32_t size);

void exe_delete_section(uint32_t idx);

IMAGE_SECTION_HEADER* exe_get_section(uint32_t idx);

void exe_split_section(uint32_t sec_idx, const char* name, size_t split_size);

uint32_t exe_get_header_size();

IMAGE_NT_HEADERS* exe_get_nt_headers();

uint32_t exe_from_rva(uint32_t rva);

uint32_t exe_to_rva(uint32_t addr);

void exe_header_update_total_section_size();

void exe_log();

void exe_emit_import_descriptors(struct list* iat_info_list);

void exe_dump_to_file(const char* filename);

#endif
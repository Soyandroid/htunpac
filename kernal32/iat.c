#define LOG_MODULE "iat"

#include <stdbool.h>
#include <windows.h>

#include "kernal32/exe.h"
#include "kernal32/iat.h"
#include "kernal32/import-cache.h"

#include "util/log.h"
#include "util/mem.h"
#include "util/str.h"

static struct list iat_found_iats_head;

static void iat_analyze_and_add_iat(HMODULE module, uint32_t** ptr)
{
	const char* dll_name = import_cache_get_dll_name(module);

	log_debug("  Analyzing IAT for %s (%p)", dll_name, module);

	struct iat_info_entry* entry = util_xmalloc(sizeof(struct iat_info_entry));

	entry->addr = (uint32_t) *ptr;
	entry->name_dll = util_str_dup(dll_name);
	entry->num_imports = 0;

	/* Iterate import list of table and collect imports */
	for (; **ptr != 0; (*ptr)++) {
		struct import* import = import_cache_get_import(**ptr);

		if (!import) {
			log_die("  Could not find import for addr %p", **ptr);
		}

		entry->imports[entry->num_imports++] = import;

        if (!import->name) {
            log_debug("    %p -> %d", *ptr, import->ordinal);
		} else {
            log_debug("    %p -> %s", *ptr, import->name);
        }
	}

	list_append(&iat_found_iats_head, &entry->head);

	log_debug("  Found %d IAT entries for %s (%p)", entry->num_imports, 
		dll_name, module);
}

static bool iat_check_iat(HMODULE module, uint32_t* ptr)
{
    for (; *ptr != 0; ptr++) {
		const struct import* import = import_cache_get_import(*ptr);

		if (import == NULL || import->module != module) {
			return false;
		}
	}

	return true;
}

void iat_find_iats()
{
	for (uint32_t i = 0; i < exe_get_section_count(); i++) {
		const IMAGE_SECTION_HEADER* section = exe_get_section(i);

        /* Scan loaded section for IATs */
        uint32_t* pos = (uint32_t*) exe_from_rva(section->VirtualAddress);
        uint32_t* end = pos + section->Misc.VirtualSize / 4;

        log_debug("Scanning for IATs in section %d (%s): %p to %p", i, 
			section->Name, pos, end);

		for (; pos < end; pos++) {
            // TODO remove this and check with empress?
			// Basic range check to filter out most non-pointers
			if (*pos > 0x100000 && *pos < 0xC0000000) {
				struct import* import = import_cache_get_import(*pos);

				if (import != NULL && iat_check_iat(import->module, pos)) {
					iat_analyze_and_add_iat(import->module, &pos);
				}
			}
		}
	}
}

struct list* iat_get_found_iats()
{
	return &iat_found_iats_head;
}

void iat_log()
{
	// TODO
}
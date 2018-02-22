#define LOG_MODULE "import-cache"

#include "import-cache.h"

#include "util/list.h"
#include "util/log.h"
#include "util/mem.h"
#include "util/str.h"

struct entry_dll {
    struct list_node head;
    HMODULE module;
    const char* name;
};

struct entry_import {
    struct list_node head;
    uint32_t addr;
    struct import import;
};

static struct list import_cache_dlls_head;
static struct list import_cache_imports_head;

static const char* import_cache_get_dll_name_internal(HMODULE module, bool warn)
{
    struct list_node* pos;
    struct entry_dll* entry;

    for (pos = import_cache_dlls_head.head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct entry_dll, head);

        if (entry->module == module) {
            break;
        }
    }

    if (pos != NULL) {
        return entry->name;
    } else {
        if (warn) {
            log_warn("No entry available for dll module %p", module);
        }

        return NULL;
    }
}

static struct import* import_cache_get_or_add_import_by_address(uint32_t addr)
{
    struct list_node* pos;
    struct entry_import* entry;

    for (pos = import_cache_imports_head.head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct entry_import, head);

        if (entry->addr == addr) {
            break;
        }
    }

    if (pos != NULL) {
        return &entry->import;
    } else {
        struct entry_import* new_entry;

        new_entry = util_xmalloc(sizeof(struct entry_import));
        new_entry->addr = addr;
        new_entry->import.module = INVALID_HANDLE_VALUE;
        new_entry->import.name = NULL;
        new_entry->import.ordinal = 0xFFFF;

        list_append(&import_cache_imports_head, &new_entry->head);

        log_debug("Created new import entry for addr %p", addr);

        return &new_entry->import;
    }
}

const char* import_cache_get_dll_name(HMODULE module)
{
    return import_cache_get_dll_name_internal(module, true);
}

struct import* import_cache_get_import(uint32_t addr)
{
    struct list_node* pos;
    struct entry_import* entry;

    for (pos = import_cache_imports_head.head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct entry_import, head);

        if (entry->addr == addr) {
            break;
        }
    }

    if (pos != NULL) {
        return &entry->import;
    } else {
        return NULL;
    }
}

void import_cache_add_dll(HMODULE module, const char* name)
{
    struct list_node* pos;
    struct entry_dll* entry;

    log_debug("Add dll: %p %s", module, name);

    for (pos = import_cache_dlls_head.head; pos != NULL; 
            pos = pos->next) {
        entry = containerof(pos, struct entry_dll, head);

        if (entry->module == module) {
            break;
        }
    }

    if (pos != NULL) {
        if (_stricmp(entry->name, name)) {
            log_warn("Different names of imports %s and %s for same module %p", 
                entry->name, name, module);
        }
    } else {
        struct entry_dll* new_entry;

        new_entry = util_xmalloc(sizeof(struct entry_dll));
        new_entry->module = module;
        new_entry->name = util_str_to_lower(util_str_dup(name));

        log_debug("Add new dll entry for %p -> %s", module, name);

        list_append(&import_cache_dlls_head, &new_entry->head);
    }
}

void import_cache_add_import_by_name(HMODULE module, void* addr, 
        const char* name)
{
    struct import* import = 
        import_cache_get_or_add_import_by_address((uint32_t) addr);

    log_debug("Add by name: %p %p %s", module, addr, name);

    import->module = module;
    
    if (!import->name) {
        import->name = util_str_dup(name);
    } else {
        if (_stricmp(import->name, name)) {
            log_warn("Different names of imports %s and %s for same module %p, "
                "address %p", import->name, name, module, addr);
        }
    }
}

void import_cache_add_import_by_ordinal(HMODULE module, void* addr, 
        uint16_t ordinal)
{
    struct import* import = 
        import_cache_get_or_add_import_by_address((uint32_t) addr);

    log_debug("Add by ordinal: %p %p %d", module, addr, ordinal);

    import->module = module;
    import->ordinal = ordinal;
}

void import_cache_log()
{
    log_debug("List of cached dlls");

    for (struct list_node*pos = import_cache_dlls_head.head; pos != NULL; 
            pos = pos->next) {
        struct entry_dll* entry = containerof(pos, struct entry_dll, head);

        log_debug("    %s -> %p", entry->name ? entry->name : "NULL", 
            entry->module);
    }

    log_debug("List of cached imports");

    for (struct list_node*pos = import_cache_imports_head.head; pos != NULL; 
            pos = pos->next) {
        struct entry_import* entry = 
            containerof(pos, struct entry_import, head);

        const char* dll_name = import_cache_get_dll_name_internal(
            entry->import.module, false);

        log_debug("    %s (%d): addr %p -> module %s (%p)", 
            entry->import.name ? entry->import.name : "NULL", 
            entry->import.ordinal, entry->addr, 
            dll_name ? dll_name : "NULL", entry->import.module);
    }
}

void import_cache_dump_dll_to_file(const char* dll_name, const char* path)
{
    // TODO for sirius to dump the unpacked dlls back to files
}
#define LOG_MODULE "exe"

#include <stdbool.h>

#include "kernal32/exe.h"
#include "kernal32/import-cache.h"

#include "util/log.h"

static const uint32_t PAGE_SIZE = 0x100;

static uint32_t exe_base;
static IMAGE_DOS_HEADER* exe_dos_header;
static IMAGE_NT_HEADERS* exe_nt_headers;
static IMAGE_SECTION_HEADER* exe_section_header;

/* ========================================================================== */

static size_t exe_round_up_page_size(size_t size)
{
    return ((size - 1) & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
}

static void* exe_directed_virtual_alloc(uint32_t va_base, uint32_t size)
{
    MEMORY_BASIC_INFORMATION mi;
    void* result;
    size_t ret;

    log_debug("exe_directed_virtual_alloc: va_base %p, size %d", va_base, size);

    /* Search for nearby free pages with sufficient space */
    while (true) {
        ret = VirtualQuery((void*) va_base, &mi, sizeof(mi));

        if (ret == 0) {
            log_die("    VirtualQuery failed!");
        } else if (mi.State != MEM_FREE) {
            log_debug("    %p: In use [%p bytes]", mi.BaseAddress, 
                mi.RegionSize);
            va_base = ((uint32_t) mi.BaseAddress) + mi.RegionSize;
        } else if (mi.RegionSize < size) {
            log_debug("    %p: Too small [%p bytes]", mi.BaseAddress,
                mi.RegionSize);
            va_base = ((uint32_t) mi.BaseAddress) + mi.RegionSize;
        } else {
            log_debug("    %p: Page found [%p bytes]", mi.BaseAddress,
                mi.RegionSize);
            result = VirtualAlloc((void*) va_base, size, 
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

            if (result == NULL) {
                log_debug("    VirtualAlloc failed!: %d", GetLastError());
                va_base = (uint32_t) mi.BaseAddress + mi.RegionSize;
            } else {
                log_debug("    VirtualAlloc successful");
                break;
            }
        }
    }

    return result;
}

static void exe_alloc_import_descriptors(struct list* iat_info_list, 
        IMAGE_IMPORT_DESCRIPTOR** descs, char** text)
{
    /* imp desc list is terminated by a null entry, we count it here */
    uint32_t dir_size = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    struct list_node* pos;
    struct iat_info_entry* entry;
    uint32_t count_descriptors = 0;

    /* Calculate total size of descriptor */
    for (pos = iat_info_list->head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct iat_info_entry, head);

        /* Count descriptor, DLL name, and string NULL terminator */
        dir_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        dir_size += strlen(entry->name_dll) + 1;

        for (size_t j = 0 ; j < entry->num_imports; j++) {
            struct import* import = entry->imports[j];

            if (import->name) {
                // TODO why +3 ?
                dir_size += strlen(import->name) + 3;
            }
        }

        count_descriptors++;
    }

    log_debug("Allocating %d byte .idata section", dir_size);

    *descs = (IMAGE_IMPORT_DESCRIPTOR*) exe_allocate_section(
        ".idata", dir_size);
    *text = (char*) (((uint32_t) *descs) + 
        (count_descriptors + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    IMAGE_DATA_DIRECTORY* import_dir = &exe_nt_headers->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    import_dir->Size = dir_size;
    import_dir->VirtualAddress = exe_to_rva((uint32_t) *descs);

    log_debug("Import data directory (rva %p, addr %p): size %d", 
        import_dir->VirtualAddress, *descs, import_dir->Size);
}

/* ========================================================================== */

void exe_init(HMODULE module)
{
    exe_base = (uint32_t) module;

    exe_dos_header = (IMAGE_DOS_HEADER*) exe_from_rva(0);
    exe_nt_headers = (IMAGE_NT_HEADERS*) exe_from_rva(exe_dos_header->e_lfanew);
    exe_section_header = (IMAGE_SECTION_HEADER*) exe_from_rva(
        exe_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    log_info("init, base %p, dos_header %p, nt_headers %p, section_header %p", 
        exe_base, exe_dos_header, exe_nt_headers, exe_section_header);
}

uint32_t exe_get_section_count()
{
    return exe_nt_headers->FileHeader.NumberOfSections;
}

void* exe_allocate_section(const char* name, uint32_t size)
{
    if (strlen(name) >= 8) {
        log_die("Invalid size for section string %d: %s", strlen(name), name);
    }

    log_debug("Allocating section %s -> size: %d", name, size);

    /* Allocate new section */
    IMAGE_SECTION_HEADER* section_header = 
        exe_section_header + exe_nt_headers->FileHeader.NumberOfSections++; 

    ZeroMemory(section_header, sizeof(IMAGE_SECTION_HEADER));

    /* Init section header */
    strcpy((char*) section_header->Name, name);
    section_header->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA 
        | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    /* Always align loaded section size to full page size */
    section_header->Misc.VirtualSize = exe_round_up_page_size(size);
    /* Size of raw data size stored in file */
    section_header->SizeOfRawData = size;

    /* Determine the next free spot in a packed exe file on disk */
    uint32_t stored_section_pos = 0;

    for (uint32_t i = 0 ; i < exe_get_section_count() ; i++) {
        uint32_t possible_pos = exe_section_header[i].PointerToRawData + 
            exe_section_header[i].SizeOfRawData;
        stored_section_pos = max(stored_section_pos, possible_pos);
    }

    /* Set attribute for section pos in exe file */
    section_header->PointerToRawData = 
        exe_round_up_page_size(stored_section_pos);

    /* Allocate some space for the loaded segment nearby the base of the exe */
    void* loaded_section = exe_directed_virtual_alloc(exe_base, 
        exe_round_up_page_size(size));

    /* Set attribute for loaded section */
    section_header->VirtualAddress = exe_to_rva((uint32_t) loaded_section);

    exe_header_update_total_section_size();

    log_debug("Allocated section %s -> size: %d", name, size);
    log_debug("stored_section_pos: %d", stored_section_pos);
    log_debug("loaded_section: %p", loaded_section);

    return loaded_section;
}

void exe_delete_section(uint32_t idx)
{
    log_debug("Delete section %d", idx);

    memmove(exe_section_header + idx, exe_section_header + idx + 1, 
        sizeof(IMAGE_SECTION_HEADER) * (exe_get_section_count() - idx - 1));

    exe_nt_headers->FileHeader.NumberOfSections--;

    exe_header_update_total_section_size();
}

IMAGE_SECTION_HEADER* exe_get_section(uint32_t idx)
{
    if (idx >= exe_get_section_count()) {
        log_die("Invalid section idx %d, total count %d", idx, 
            exe_get_section_count());
    }

	return exe_section_header + idx;
}

uint32_t exe_get_header_size()
{
    return sizeof(IMAGE_NT_HEADERS) + exe_dos_header->e_lfanew
        + exe_get_section_count() * sizeof(IMAGE_SECTION_HEADER);
}

IMAGE_NT_HEADERS* exe_get_nt_headers()
{
    return exe_nt_headers;
}

uint32_t exe_from_rva(uint32_t rva)
{
    return exe_base + rva;
}

uint32_t exe_to_rva(uint32_t addr)
{
    return addr - exe_base;
}

void exe_header_update_total_section_size()
{
    DWORD size = 0;

    log_debug("Fixing up sections (old SizeOfImage %d)", 
        exe_nt_headers->OptionalHeader.SizeOfImage);

    /* SizeOfImage seems to refer to the VIRTUAL size, which is a bit of a 
       meaningless quantity... */

    for (uint32_t i = 0 ; i < exe_get_section_count() ; i++) {
        IMAGE_SECTION_HEADER* cur_section_header = exe_section_header + i;
        size = max(size, cur_section_header->VirtualAddress + 
            cur_section_header->Misc.VirtualSize);

        if (i > 0) {
            IMAGE_SECTION_HEADER* prev_section_header = cur_section_header - 1;
            prev_section_header->Misc.VirtualSize = 
                max(prev_section_header->Misc.VirtualSize,
                    cur_section_header->VirtualAddress - 
                    prev_section_header->VirtualAddress);
        }
    }

    /* Update the size of the image including all headers. Must be a multiple
       of SectionAlignment */
    exe_nt_headers->OptionalHeader.SizeOfImage = 
        exe_round_up_page_size(size);

    log_debug("Fixing up sections done (new SizeOfImage: %d)", 
        exe_nt_headers->OptionalHeader.SizeOfImage);
}

void exe_log()
{
    log_debug("Executable breakdown (base %p)", exe_base);

    log_debug("DOS header (rva %p, addr %p)", 
        exe_to_rva((uint32_t) exe_dos_header), exe_dos_header);

    log_debug("NT header (rva %p, addr %p)", (void*) exe_dos_header->e_lfanew, 
        exe_nt_headers);

    log_debug("    OEP, rva %p, addr %p", 
        exe_nt_headers->OptionalHeader.AddressOfEntryPoint, 
        exe_from_rva(exe_nt_headers->OptionalHeader.AddressOfEntryPoint));
    log_debug("    Size of image: %d", 
        exe_nt_headers->OptionalHeader.SizeOfImage);
    log_debug("    Num sections: %d", exe_get_section_count());

    for (uint32_t i = 0; i < exe_get_section_count(); i++) {
        IMAGE_SECTION_HEADER* section = exe_get_section(i);
        log_debug("    Section %d (rva %p, addr %p)", i, 
            section->VirtualAddress, exe_from_rva(section->VirtualAddress));
        log_debug("      Name: %s", section->Name);
        log_debug("      Size (raw data): %d", section->SizeOfRawData);
        log_debug("      Pos (in raw data): %p", section->PointerToRawData);
        log_debug("      Virtual size: %d", section->Misc.VirtualSize);
    }
}

void exe_emit_import_descriptors(struct list* iat_info_list)
{
    IMAGE_IMPORT_DESCRIPTOR* desc;
    char* text;

    exe_alloc_import_descriptors(iat_info_list, &desc, &text);

    struct list_node* pos;
    struct iat_info_entry* entry;

    /* Iterate all IATs of the dlls loaded */
    for (pos = iat_info_list->head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct iat_info_entry, head);
        uint32_t* rva = (uint32_t*) entry->addr;

        log_debug(
            "Emitting import descriptors and import records for %s (rva %p)",
            entry->name_dll, rva);

        desc->Name = exe_to_rva((uint32_t) text);
        desc->FirstThunk = exe_to_rva(entry->addr);

        strcpy(text, entry->name_dll);
        text += strlen(entry->name_dll) + 1;

        /* Imports of dll */
        for (uint32_t j = 0 ; j < entry->num_imports; j++, rva++) {
            struct import* import = entry->imports[j];

            if (!import->name) {
                /* Import by ordinal */
                *rva = 0x80000000 | import->ordinal;
            } else {
                /* Convert back to an IMPORT_BY_NAME RVA */
                *rva = exe_to_rva((uint32_t) text);

                text += 2;
                strcpy(text, import->name);
                text += strlen(import->name) + 1;
            }
        }
    }
}

void exe_dump_to_file(const char* filename)
{
    OVERLAPPED ovl;
    DWORD out;

    log_info("Dumping exe to file: %s", filename);

    /* Delete existing files to avoid failure on CreateFile */
    DeleteFile(filename);

    HANDLE handle = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
        0, NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        log_die("Opening output file %s failed: %d", filename, GetLastError());
    }

    /* Emit header */
    if (!WriteFile(handle, (BYTE*) exe_from_rva(0), exe_get_header_size(), &out, 
            NULL)) {
        log_die("    Writing header failed: %d", GetLastError());
    }

    memset(&ovl, 0, sizeof(OVERLAPPED));

    /* Emit sections */
    for (size_t i = 0; i < exe_get_section_count(); i++) {
        const IMAGE_SECTION_HEADER* section = exe_get_section(i);

        log_debug("    Writing of section %d: %s (size: %d)", i, section->Name,
            section->SizeOfRawData);

        ovl.Offset = section->PointerToRawData;
        if (!WriteFile(handle, (BYTE*) exe_from_rva(section->VirtualAddress), 
                section->SizeOfRawData , &out, &ovl)) {
            log_die("    Writing failed: %d", GetLastError());
        }
    }

    CloseHandle(handle);

    log_debug("Dumping to exe finished");
}
#define LOG_MODULE "exe"

#include <stdbool.h>

#include "kernal32/exe.h"
#include "kernal32/import-cache.h"

#include "util/log.h"

static const uint32_t PAGE_SIZE = 0x1000;

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
        IMAGE_IMPORT_DESCRIPTOR** descs, uint32_t** list_rvas, char** text)
{
    /* imp desc list is terminated by a null entry, we count it here */
    uint32_t dir_size = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    struct list_node* pos;
    struct iat_info_entry* entry;
    uint32_t count_descriptors = 0;
    uint32_t count_rva_list = 0;

    /* Calculate total size of descriptor */
    for (pos = iat_info_list->head; pos != NULL; pos = pos->next) {
        entry = containerof(pos, struct iat_info_entry, head);

        /* Count descriptor, DLL name, and string NULL terminator */
        dir_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        dir_size += strlen(entry->name_dll) + 1;

        for (size_t j = 0 ; j < entry->num_imports; j++) {
            struct import* import = entry->imports[j];

            if (import->name) {
                /* +3: WORD for hint value (index into AddressOfNames array) 
                   and null terminator */
                dir_size += strlen(import->name) + 3;
            }
            // TODO if not name we still need some space +2 for ordinal?
        
            dir_size += sizeof(uint32_t);
            count_rva_list++;
        }

        /* Last entry of each list must be set to 0 to terminte the list */
        dir_size += sizeof(uint32_t);
        count_rva_list++;

        count_descriptors++;
    }

    /* count_descriptors + 1: last descriptor is set to null to terminate the 
       list */
    count_descriptors++;
    dir_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    log_debug("Allocating %d byte .idata section", dir_size);

    *descs = (IMAGE_IMPORT_DESCRIPTOR*) exe_allocate_section(
        ".idata", dir_size);
        
    *list_rvas = (uint32_t*) (((uint32_t) *descs) + 
        count_descriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    /* text stuff follows the descriptors */
    *text = (char*) (((uint32_t) *list_rvas) + 
        count_rva_list * sizeof(uint32_t));

    /* Add to data directory */
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

void exe_split_section(uint32_t sec_idx, const char* name, size_t split_size)
{
    IMAGE_SECTION_HEADER* section = exe_get_section(sec_idx);

    size_t size_first_chunk = exe_round_up_page_size(split_size);
    size_t size_second_chunk = section->Misc.VirtualSize - size_first_chunk;

    log_debug("Splitting section %d, size %d (%X) into %d (%X) and %d (%X)", sec_idx, 
        section->Misc.VirtualSize, section->Misc.VirtualSize, size_first_chunk, 
        size_first_chunk, size_second_chunk, size_second_chunk);

    section->Misc.VirtualSize = size_first_chunk;
    section->SizeOfRawData = size_first_chunk;

    IMAGE_SECTION_HEADER* second_section = 
        exe_section_header + exe_nt_headers->FileHeader.NumberOfSections++; 

    ZeroMemory(second_section, sizeof(IMAGE_SECTION_HEADER));

    /* Init section header */
    strcpy((char*) second_section->Name, name);
    second_section->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA 
        | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    /* Always align loaded section size to full page size */
    second_section->Misc.VirtualSize = size_second_chunk;
    /* Size of raw data size stored in file */
    second_section->SizeOfRawData = size_second_chunk;

    /* Set attribute for section pos in exe file */
    second_section->PointerToRawData = 
        section->PointerToRawData + size_first_chunk;

    /* Set attribute for loaded section */
    second_section->VirtualAddress = 
        (uint32_t) section->VirtualAddress + size_first_chunk;

    log_debug("New split section %s -> size: %d", name, size_second_chunk);
    log_debug("1st stored_section_pos: %d", section->PointerToRawData);
    log_debug("1st loaded_section: %p", section->VirtualAddress);
    log_debug("2nd stored_section_pos: %d", second_section->PointerToRawData);
    log_debug("2nd loaded_section: %p", second_section->VirtualAddress);
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

    IMAGE_SECTION_HEADER* delete_section = exe_get_section(idx);
    uint32_t space_freed = delete_section->SizeOfRawData;

    memmove(exe_section_header + idx, exe_section_header + idx + 1, 
        sizeof(IMAGE_SECTION_HEADER) * (exe_get_section_count() - idx - 1));

    exe_nt_headers->FileHeader.NumberOfSections--;

    for (int i = idx; i < exe_get_section_count(); i++) {
        IMAGE_SECTION_HEADER* section = exe_get_section(i);

        section->PointerToRawData -= space_freed;
    }

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

    log_debug("----------------------------------DOS Header Information----------------------------------");
    log_debug("DOS header (rva %p, addr %p)", 
        exe_to_rva((uint32_t) exe_dos_header), exe_dos_header);
    log_debug("Magic number: %#x (%s)", exe_dos_header->e_magic, 
        exe_dos_header->e_magic == 0x5a4d ? "MZ" : "-");
    log_debug("Bytes on last page of file: %d", exe_dos_header->e_cblp);
    log_debug("Pages in file: %#x", exe_dos_header->e_cp);
    log_debug("Relocations: %#x", exe_dos_header->e_crlc);
    log_debug("Size of header in paragraphs: %#x", 
        exe_dos_header->e_cparhdr);
    log_debug("Minimum extra paragraphs needed: %#x", 
        exe_dos_header->e_minalloc);
    log_debug("Maximum extra paragraphs needed: %#x", 
        exe_dos_header->e_maxalloc);
    log_debug("Initial (relative) SS value: %#x", exe_dos_header->e_ss);
    log_debug("Initial SP value: %#x", exe_dos_header->e_sp);
    log_debug("Checksum: %#x", exe_dos_header->e_csum);
    log_debug("Initial IP value: %#x", exe_dos_header->e_ip);
    log_debug("Initial (relative) CS value: %#x", exe_dos_header->e_cs);
    log_debug("File address of relocation table: %#x", 
        exe_dos_header->e_lfarlc);
    log_debug("Overlay number: %#x", exe_dos_header->e_ovno);
    log_debug("OEM identifier (for e_oeminfo): %#x", 
        exe_dos_header->e_oemid);
    log_debug("OEM information; e_oemid specific: %#x",	
        exe_dos_header->e_oeminfo);
    log_debug("File address of new exe header: %#lx",	
        exe_dos_header->e_lfanew);

    log_debug("---------------------------------- NT Header Information----------------------------------");
    log_debug("NT header (rva %p, addr %p)", (void*) exe_dos_header->e_lfanew, 
        exe_nt_headers);

    log_debug("Signature: %#lx (%s)", exe_nt_headers->Signature, "PE");
    log_debug("Computer architecture type: ");

    IMAGE_FILE_HEADER image_file_header = exe_nt_headers->FileHeader;

    switch(image_file_header.Machine){
        case IMAGE_FILE_MACHINE_I386:
            log_debug("x86");
            break;
        case IMAGE_FILE_MACHINE_IA64:
            log_debug("Intel Itanium");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            log_debug("x64");
            break;
    }

    log_debug("Number of sections: %#x", image_file_header.NumberOfSections);
    log_debug("Timestamp: %lu", image_file_header.TimeDateStamp);
    log_debug("Symbol table offset: %#lx", image_file_header.PointerToSymbolTable);
    log_debug("Number of symbols: %#lx", image_file_header.NumberOfSymbols);
    log_debug("Size of optional headers: %#x", image_file_header.SizeOfOptionalHeader);

    log_debug("Image characteristics: ");

    if ((image_file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE) {
        log_debug("The file is executable.");
    }

    if ((image_file_header.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        log_debug("The application can handle addresses larger than 2 GB.");
    }

    if ((image_file_header.Characteristics & IMAGE_FILE_SYSTEM) == IMAGE_FILE_SYSTEM) {
        log_debug("The image is a system file.");
    }

    if ((image_file_header.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) {
        log_debug("The image is a DLL file.");
    }

    log_debug("------------------------------PE Optional Header Information------------------------------");
    log_debug("    OEP, rva %p, addr %p", 
        exe_nt_headers->OptionalHeader.AddressOfEntryPoint, 
        exe_from_rva(exe_nt_headers->OptionalHeader.AddressOfEntryPoint));
    log_debug("Image file state: %#x (%s)", exe_nt_headers->OptionalHeader.Magic, exe_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE64" : "PE32" );
    log_debug("Major Linker Version: %#x (%d)", exe_nt_headers->OptionalHeader.MajorLinkerVersion, exe_nt_headers->OptionalHeader.MajorLinkerVersion);
    log_debug("Minor Linker Version: %#x (%d)", exe_nt_headers->OptionalHeader.MinorLinkerVersion, exe_nt_headers->OptionalHeader.MinorLinkerVersion);
    log_debug("Size of code section(.text): %lu bytes", exe_nt_headers->OptionalHeader.SizeOfCode);
    log_debug("Size of initialized data section: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfInitializedData);
    log_debug("Size of uninitialized data section: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfUninitializedData);
    log_debug("Address of entry point: %#lx", exe_nt_headers->OptionalHeader.AddressOfEntryPoint);
    log_debug("Base address of code section: %#lx", exe_nt_headers->OptionalHeader.BaseOfCode);
    log_debug("Base address of data section: %#lx", exe_nt_headers->OptionalHeader.BaseOfData);
    log_debug("Base address of image in memory: %#lx", exe_nt_headers->OptionalHeader.ImageBase);
    log_debug("Sections alignment in memory (bytes): %#lx", exe_nt_headers->OptionalHeader.SectionAlignment);
    log_debug("Raw data of sections alignment in image file (bytes): %#lx", exe_nt_headers->OptionalHeader.FileAlignment);
    log_debug("OS major version required: %#x (%d)", exe_nt_headers->OptionalHeader.MajorOperatingSystemVersion, exe_nt_headers->OptionalHeader.MajorOperatingSystemVersion);
    log_debug("OS minor version required: %#x (%d)", exe_nt_headers->OptionalHeader.MinorOperatingSystemVersion, exe_nt_headers->OptionalHeader.MinorOperatingSystemVersion);
    log_debug("Image major version number: %#x (%d)", exe_nt_headers->OptionalHeader.MajorImageVersion, exe_nt_headers->OptionalHeader.MajorImageVersion);
    log_debug("Image minor version number: %#x (%d)", exe_nt_headers->OptionalHeader.MinorImageVersion, exe_nt_headers->OptionalHeader.MinorImageVersion);
    log_debug("Subsystem major version number: %#x (%d)", exe_nt_headers->OptionalHeader.MajorSubsystemVersion, exe_nt_headers->OptionalHeader.MajorSubsystemVersion);
    log_debug("Subsystem minor version number: %#x (%d)", exe_nt_headers->OptionalHeader.MinorSubsystemVersion, exe_nt_headers->OptionalHeader.MinorSubsystemVersion);
    log_debug("Image size: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfImage);
    log_debug("Size of headers: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfHeaders);
    log_debug("Image file checksum: %#lx", exe_nt_headers->OptionalHeader.CheckSum);
    log_debug("Subsystem: %#x (",exe_nt_headers->OptionalHeader.Subsystem);
    
    switch(exe_nt_headers->OptionalHeader.Subsystem){
        case IMAGE_SUBSYSTEM_NATIVE:
            log_debug("Device driver - Native system process)");
            break;

        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            log_debug("Windows GUI)");
            break;

        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            log_debug("Windows CUI)");
            break;

        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
            log_debug("Windows CE)");
            break;
    }

    log_debug("Dll characteristics: %#x", exe_nt_headers->OptionalHeader.DllCharacteristics);
    log_debug("Number of bytes reserved for stack: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfStackReserve);
    log_debug("Number of bytes to commit for stack: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfStackCommit);
    log_debug("Number of bytes to reserve for local heap: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfHeapReserve);
    log_debug("Number of bytes to commit for local heap: %lu bytes", exe_nt_headers->OptionalHeader.SizeOfHeapCommit);
    log_debug("Number of directory entries: %lu", exe_nt_headers->OptionalHeader.NumberOfRvaAndSizes);

    log_debug("----------------------------------Image Data Directories----------------------------------");
    for (int i = 0; i < exe_nt_headers->OptionalHeader.NumberOfRvaAndSizes; i++) {
        log_debug("Directory %d: %#lx (%lu bytes)", i, 
            exe_nt_headers->OptionalHeader.DataDirectory[i].VirtualAddress, 
            exe_nt_headers->OptionalHeader.DataDirectory[i].Size);
    }
    
    for (uint32_t i = 0; i < exe_get_section_count(); i++) {
        log_debug("-----------------------------------Image Section Header-----------------------------------");
        IMAGE_SECTION_HEADER* section = exe_get_section(i);
        log_debug("Section %d", i);
        log_debug("Section name: %s", section->Name);
        log_debug("File Address: %#lx", section->Misc.PhysicalAddress);
        log_debug("Section size in memory: %lu bytes", section->Misc.VirtualSize);
        log_debug("Virtual Address: %#lx", section->VirtualAddress);
        log_debug("Size of initialized data on disk: %lu bytes", section->SizeOfRawData);
        log_debug("Pointer to raw data: %#lx", section->PointerToRawData);
        log_debug("Pointer to relocations: %#lx", section->PointerToRelocations);
        log_debug("Pointer to line numbers: %#lx", section->PointerToLinenumbers);
        log_debug("Number of relocation entries: %#x", section->NumberOfRelocations);
        log_debug("Number of line number entries: %#x", section->NumberOfLinenumbers);
        log_debug("Image characteristics: ");

        if((section->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
            log_debug("The section contains executable code.");
        if((section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA)
            log_debug("The section contains initialized data.");
        if((section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            log_debug("The section contains uninitialized data.");
        if((section->Characteristics & IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO)
            log_debug("The section contains comments or other information.");
        if((section->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
            log_debug("The section can be shared in memory.");
        if((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
            log_debug("The section can be executed as code.");
        if((section->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)
            log_debug("The section can be read.");
        if((section->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)
            log_debug("The section can be written to.");
    }
    
    /*
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
    */
}

void exe_emit_import_descriptors(struct list* iat_info_list)
{
    IMAGE_IMPORT_DESCRIPTOR* desc;
    uint32_t* list_rvas;
    char* text;

    exe_alloc_import_descriptors(iat_info_list, &desc, &list_rvas, &text);

    struct list_node* pos;
    struct iat_info_entry* entry;

    /* Iterate all IATs of the dlls loaded */
    for (pos = iat_info_list->head; pos != NULL; pos = pos->next, desc++) {
        entry = containerof(pos, struct iat_info_entry, head);
        uint32_t* rva = (uint32_t*) entry->addr;

        desc->OriginalFirstThunk = exe_to_rva((uint32_t) list_rvas);        
        desc->Name = exe_to_rva((uint32_t) text);
        desc->FirstThunk = exe_to_rva(entry->addr);

        log_debug(
            "Emitting import descriptors and import records for %s (rva %p, "
            "original first thunk %p, name %p, first thunk %p)", 
            entry->name_dll, rva, desc->OriginalFirstThunk, desc->Name, 
            desc->FirstThunk);

        /* Copy name to text sub-section */
        strcpy(text, entry->name_dll);
        text += strlen(entry->name_dll) + 1;

        /* Imports of dll */
        for (uint32_t j = 0 ; j < entry->num_imports; j++, rva++, list_rvas++) {
            struct import* import = entry->imports[j];

            if (!import->name) {
                /* Import by ordinal */
                *rva = 0x80000000 | import->ordinal;
            } else {
                /* Convert back to an IMPORT_BY_NAME RVA */
                *rva = exe_to_rva((uint32_t) text);

                /* skip hint value field */
                text += 2;
                strcpy(text, import->name);

                log_debug("Imports RVA list (%d): %p -> %p (%s)", j, rva, *rva, text);

                text += strlen(import->name) + 1;
            }

            *list_rvas = *rva;
        }

        /* leave one entry null to terminate the list by skipping it. already
           considered on allocation */
        list_rvas++;
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

    // DWORD chunk = 1024 * 1024;

    // for (int i = 0; i < 100; i++) {
    //     if (!WriteFile(handle, (BYTE*) 0x00404000 + chunk * i, chunk, &out, 
    //             NULL)) {
    //         log_die("    Writing header failed: %d", GetLastError());
    //     }
    // }

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

        log_debug("    Written: %d", out);
    }

    CloseHandle(handle);

    log_debug("Dumping to exe finished");
}
#define LOG_MODULE "kernal32"

#include <stdbool.h>
#include <windows.h>

#include "kernal32/exe.h"
#include "kernal32/import-cache.h"

#include "util/log.h"

struct detour_entry {
    const char* name;
    void * proc;
};

static HANDLE WINAPI my_CreateFileA(char* lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile);
static void WINAPI my_SetLastError(DWORD code);

HMODULE WINAPI my_GetModuleHandleA(const char* name);
HMODULE WINAPI my_LoadLibraryA(const char* name);
void* WINAPI my_GetProcAddress(HMODULE module, const char* param);

static const struct detour_entry get_proc_detours[] = {
    { "GetModuleHandleA", my_GetModuleHandleA },
    { "LoadLibraryA", my_LoadLibraryA },
    { "GetProcAddress", my_GetProcAddress },
    { "CreateFileA", my_CreateFileA },
    { "SetLastError", my_SetLastError },
    { NULL, NULL }
};

static bool initialized = false;

/* ========================================================================== */

static void set_guard_state(bool on)
{
    log_debug("Setting guard page state: %d", on);

    /* -2: Ignore htpec segments at the end */
    for (int i = 0 ; i < exe_get_section_count() - 2 ; i++) {
        DWORD old;
        const IMAGE_SECTION_HEADER *section = exe_get_section(i);

        VirtualProtect((void*) exe_from_rva(section->VirtualAddress), 
            section->Misc.VirtualSize, PAGE_READWRITE | (-on & PAGE_GUARD), 
            &old);
    }
}

static void prepare_for_dumping(uint32_t oep)
{
    log_info("Preparing exe for dumping, oep: %p", oep);

    IMAGE_NT_HEADERS* headers = exe_get_nt_headers();

    /* Wipe sections added by htpec */
    log_debug(    "Wiping htpec sections");
    exe_delete_section(exe_get_section_count() - 1);
    exe_delete_section(exe_get_section_count() - 1);

    /* Restore the original entry point */
    headers->OptionalHeader.AddressOfEntryPoint = exe_to_rva(oep);
    log_debug("    Restored OEP: %p", 
        headers->OptionalHeader.AddressOfEntryPoint);

    /* Nuke all data directories */
    log_debug("    Clearing image data directory");
    ZeroMemory(headers->OptionalHeader.DataDirectory, 
        sizeof(IMAGE_DATA_DIRECTORY) * 16);

    /* Trim off any BSS, enable writeability
       (If the section containing the IATs is read-only, the EXE will crash
        early on in the bootstrapping process). */
    for (uint32_t i = 0 ; i < exe_get_section_count() ; i++) {
        IMAGE_SECTION_HEADER* section = exe_get_section(i);
        uint32_t bottom = exe_from_rva(section->VirtualAddress);
        uint32_t top = bottom + section->Misc.VirtualSize - 1;

        while (top > bottom && ! *((uint8_t*) top)) {
            top--;
        }

        section->SizeOfRawData = top - bottom + 1;
        section->Characteristics |= IMAGE_SCN_MEM_WRITE;

        log_debug("    BSS fix and write enable for section %d", i);
    }

    log_info("Done preparing exe for dumping");
}

/* ========================================================================== */

static HANDLE WINAPI my_CreateFileA(char* lpFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, 
        HANDLE hTemplateFile)
{
    HANDLE hFile;
    char exeFileName[MAX_PATH];
    char* pos;

    log_debug("CreateFileA: %s", lpFileName);

    GetModuleFileNameA(NULL, exeFileName, MAX_PATH);

    if (!_stricmp(lpFileName, exeFileName)) {
        pos = exeFileName + strlen(exeFileName) - 3;
        strcpy(pos, "bak");

        log_debug("Diverted read to .bak file: %s", exeFileName);
        lpFileName = exeFileName;
    }

    hFile = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
        hTemplateFile);

    log_debug("CreateFileA: %s -> %p", lpFileName, hFile);

    return hFile;
}

/* We set things up so that calling the OEP raises an exception which is
   handled here. */
static LONG WINAPI dump(EXCEPTION_POINTERS* ex_pointers)
{
    log_debug("Entered OEP hook: eip %p", ex_pointers->ContextRecord->Eip);

    /* Revert protection to avoid further failures */
    set_guard_state(false);

    /* Cleanup some stuff introduced by htpec */
    prepare_for_dumping(ex_pointers->ContextRecord->Eip);
    
    exe_log();
    import_cache_log();

    iat_find_iats();
    iat_log();

    exe_emit_import_descriptors(iat_get_found_iats());
    exe_dump_to_file("dump.exe");

    ExitProcess(0);
}

static void WINAPI my_SetLastError(DWORD code)
{
    static int nCalls = 0;

    /* The fourth call to this proc is made immediately before HtPec
       jumps to the OEP. */

    log_info("SetLastError call count: %d", ++nCalls);

    if (nCalls == 4) {
        /* Protect the original entry point to trigger the exception handler */
        set_guard_state(true);
        SetUnhandledExceptionFilter(dump);

        log_info("Inserted OEP hook");
    }

    SetLastError(code);
}

/* ========================================================================== */

HMODULE WINAPI my_GetModuleHandleA(const char* name)
{
    log_debug("GetModuleHandleA: %s", name);

    HMODULE module = GetModuleHandleA(name);

    if (name && module) {
        /* Collect dlls */
        import_cache_add_dll(module, name);
    } 

    log_debug("GetModuleHandleA: %s -> %p", name, module);

    return module;
}

HMODULE WINAPI my_LoadLibraryA(const char* name)
{
    log_debug("LoadLibraryA: %s", name);

    HMODULE module = LoadLibraryA(name);

    if (!module) {
        log_debug("%s: DLL not found!", name);
    } else {
        /* Collect dlls */
        import_cache_add_dll(module, name);
    }

    log_debug("LoadLibraryA: %s -> %p", name, module);

    return module;
}

BOOL WINAPI my_GetVersionExA(OSVERSIONINFOA* ver)
{
    log_debug("GetVersionExA");

    return GetVersionExA(ver);
}

void* WINAPI my_GetProcAddress(HMODULE module, const char* param)
{
    if (!HIWORD(param)) {
        /* By ordinal */

        uint16_t ordinal = LOWORD(param);

        log_debug("GetProcAddress (ordinal): %p, %d", module, ordinal);

        void* proc = GetProcAddress(module, param);

        if (!proc) {
            log_warn(
                "GetProcAddress: ordinal %d of module %p failed to resolve", 
                module, ordinal);
        } else {
            /* Collect imports */
            import_cache_add_import_by_ordinal(module, proc, ordinal);
        }

        return proc;
    } else {
        /* By name */
        /* Trap a few detours we want to take */
        const struct detour_entry* entry;
        void* proc_detour = NULL;

        log_debug("GetProcAddress (name): %p, %s", module, param);

        for (entry = get_proc_detours; entry->name; entry++) {
            if (!_stricmp(entry->name, param)) {
                proc_detour = entry->proc;
                break;
            }
        }

        void* orig_proc = GetProcAddress(module, param);

        if (!orig_proc) {
            log_warn("GetProcAddress: name %s of module %p failed to resolve",
                param, module);
        } else {
            /* Collect imports */
            import_cache_add_import_by_name(module, orig_proc, param);
        }

        /* Detour if on list */
        if (proc_detour) {
            return proc_detour;
        } else {
            return orig_proc;
        }
    }
}

/* ========================================================================== */

BOOL WINAPI DllMain(HMODULE hSelf, DWORD reason, CONTEXT* pInitContext)
{
    if (reason == DLL_PROCESS_ATTACH && !initialized) {
        initialized = true;
        util_log_set_file("kernal32.log");
        log_info("Init");

        exe_init(GetModuleHandleA(NULL));
    }

    return TRUE;
}

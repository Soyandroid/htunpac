#define LOG_MODULE "kernal32"

#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "kernal32/exe.h"
#include "kernal32/import-cache.h"
#include "kernal32/kernal32.h"
#include "kernal32/monitor.h"

#include "util/fs.h"
#include "util/log.h"
#include "util/str.h"

struct detour_entry {
    const char* name;
    void * proc;
};

HMODULE WINAPI kernal32_GetModuleHandleA(const char* name);
HMODULE WINAPI kernal32_LoadLibraryA(const char* name);
BOOL WINAPI kernal32_GetVersionExA(OSVERSIONINFOA* ver);
void* WINAPI kernal32_GetProcAddress(HMODULE module, const char* param);

static const struct detour_entry get_proc_detours[] = {
    { "GetModuleHandleA", kernal32_GetModuleHandleA },
    { "LoadLibraryA", kernal32_LoadLibraryA },
    { "GetProcAddress", kernal32_GetProcAddress },
    { "GetVersionExA", kernal32_GetVersionExA },

    { "CreateFileA", mon_CreateFileA },
    { "WriteFile", mon_WriteFile },
    { "ReadFile", mon_ReadFile },
    { "DeleteFileA", mon_DeleteFileA },
    { "GetTempFileNameA", mon_GetTempFileNameA },
    { "GetTempPathA", mon_GetTempPathA },
    { "SetFilePointer", mon_SetFilePointer },
    { "CloseHandle", mon_CloseHandle },
    { "VirtualProtect", mon_VirtualProtect },
    { "Beep", mon_Beep },
    { "GetCurrentProcess", mon_GetCurrentProcess },
    { "GetCurrentProcessId", mon_GetCurrentProcessId },
    { "GetTickCount", mon_GetTickCount },
    { "SystemTimeToFileTime", mon_SystemTimeToFileTime },
    { "GetLocalTime", mon_GetLocalTime },
    { "IsDebuggerPresent", mon_IsDebuggerPresent },
    { "CheckRemoteDebuggerPresent", mon_CheckRemoteDebuggerPresent },
    { "SetUnhandledExceptionFilter", mon_SetUnhandledExceptionFilter },
    { "UnhandledExceptionFilter", mon_UnhandledExceptionFilter },
    { "GetSystemInfo", mon_GetSystemInfo },
    { "GetProcessAffinityMask", mon_GetProcessAffinityMask },
    { "SetProcessAffinityMask", mon_SetProcessAffinityMask },
    { "UnmapViewOfFile", mon_UnmapViewOfFile },
    { "ExitProcess", mon_ExitProcess },
    { "SetLastError", mon_SetLastError },
    { "DbgUiRemoteBreakin", mon_DbgUiRemoteBreakin },
    { "GetProcessHeap", mon_GetProcessHeap },
    { "HeapAlloc", mon_HeapAlloc },
    { "HeapFree", mon_HeapFree },
    { "GetKernelObjectSecurity", mon_GetKernelObjectSecurity },
    { "GetSecurityDescriptorDacl", mon_GetSecurityDescriptorDacl },
    { "GetAce", mon_GetAce },
    { "SetKernelObjectSecurity", mon_SetKernelObjectSecurity },
    { "GetModuleFileName", mon_GetModuleFileName },
    { "GetLastError", mon_GetLastError },
    { "SetErrorMode", mon_SetErrorMode },
    { "FreeLibrary", mon_FreeLibrary },
    { "Sleep", mon_Sleep },
    { "RegQueryValueEx", mon_RegQueryValueEx },
    { "RegSetValueEx", mon_RegSetValueEx },
    { "RegCloseKey", mon_RegCloseKey },
    { "RegOpenKeyEx", mon_RegOpenKeyEx },
    { "NtQuerySystemInformation", mon_NtQuerySystemInformation },
    { "GetFileSize", mon_GetFileSize },
    { "VirtualAlloc", mon_VirtualAlloc },
    { "VirtualFree", mon_VirtualFree },
    { "DeviceIoControl", mon_DeviceIoControl },
    { "GetWindowsDirectory", mon_GetWindowsDirectory },
    { "WaitForSingleObject", mon_WaitForSingleObject },
    { "CreateMutex", mon_CreateMutex },
    { "ReleaseMutex", mon_ReleaseMutex },
    { "RtlUnwind", mon_RtlUnwind },
    { "VirtualAllocEx", mon_VirtualAllocEx },
    { "wsprintfA", mon_wsprintfA },
    { "wsprintfW", mon_wsprintfW },
    { "ResumeThread", mon_ResumeThread },
    { "SetEvent", mon_SetEvent },
    { "GetThreadContext", mon_GetThreadContext },
    { "WriteProcessMemory", mon_WriteProcessMemory },
    { "VirtualProtectEx", mon_VirtualProtectEx },
    { "CreateProcessA", mon_CreateProcessA },
    { "DuplicateHandle", mon_DuplicateHandle },
    { "CreateEventA", mon_CreateEventA },
    { "MoveFileA", mon_MoveFileA },
    { "CreateFileMappingA", mon_CreateFileMappingA },
    { "TerminateProcess", mon_TerminateProcess },
    { "ReadProcessMemory", mon_ReadProcessMemory },
    { "GetCommandLineA", mon_GetCommandLineA },
    { "GetModuleHandleA", mon_GetModuleHandleA },
    { "GetModuleFileNameA", mon_GetModuleFileNameA },
    { "GetFullPathNameA", mon_GetFullPathNameA },
    { "GlobalFree", mon_GlobalFree },
    { "GlobalAlloc", mon_GlobalAlloc },
    { NULL, NULL }
};

static bool initialized = false;

/* ========================================================================== */

static void set_guard_state(bool on)
{
    log_debug("Setting guard page state: %d", on);

    /* -2: Ignore htpec segments at the end */
    for (int i = 0 ; i < exe_get_section_count(); i++) {
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
    log_debug(    "Wiping htpec section");
    // kill last section which crashes exe on boot (wtf?)
    exe_delete_section(exe_get_section_count() - 1);

    exe_log();

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
    uint32_t pos_raw = 0x1000;

    for (uint32_t i = 0 ; i < exe_get_section_count() ; i++) {
        IMAGE_SECTION_HEADER* section = exe_get_section(i);
        uint32_t bottom = exe_from_rva(section->VirtualAddress);
        uint32_t top = bottom + section->Misc.VirtualSize - 1;

        log_debug("    BSS fix for %i, bottom %d, top %d, old raw size: %X", i, 
            bottom, top, section->SizeOfRawData);

        while (top > bottom && ! *((uint8_t*) top)) {
            top--;
        }

        uint32_t newSize = top - bottom + 1;

        section->SizeOfRawData = newSize;

        /* Fix unaligned sections in raw data (yes, these must be aligned, 
           too). Furthermore, this fixes a bug with sections overlapping and
           overwriting when loading into the process if not filled up to full
           page sizes AND aligned to non full page sizes (must be fixed as 
           well) */
        section->PointerToRawData = pos_raw;
        section->Characteristics |= IMAGE_SCN_MEM_WRITE;

        pos_raw += newSize;

        log_debug("    BSS fix and write enable for section %d, new size %d, "
            "raw pos %X", i, section->SizeOfRawData, section->PointerToRawData);
    }

    exe_log();

    /* Simply dumping it would yield a approx 43 MB huge executable which
       contains approx. 41 MB of zeros in the middle of the main section.
       This can't simply be trimmed because the end of the section contains
       valid static data which is actually referenced by the main application.
       Thus, we split that huge segment into 3 parts: the first part contains
       the major chunk of valid data, the second part is just zeros and the
       third part contains the static data of the end of the original segment.
       Now, we can simply remove that segment full of zeros before dumping the
       other segments to file. The zero section will be reconstructed in
       virtual memory once the executable is loaded.
       The offsets for splitting are simply determined by dumping the 43 MB
       exe, loading it up in CFF explorer for example and looking for some
       suitable borders in the huge segment. The border offsets must be
       page aligned. */

    /* for 2008111900 and 2008112600 */
    // exe_split_section(3, ".split", 0x18B000);
    // exe_split_section(4, ".split2", 0x27C6000);
    // exe_delete_section(4);

    /* for 2008120800 and 2009010600 */
    // exe_split_section(3, ".split", 0x18B000);
    // exe_split_section(4, ".split2", 0x27C5000);
    // exe_delete_section(4);

    /* for 2009072200
       Note: This should work with the previous revisions as well but adds
       one to two more empty pages to the executable which are not necessary */
    exe_split_section(3, ".split", 0x18B000);
    exe_split_section(4, ".split2", 0x27C4000);
    exe_delete_section(4);

    log_info("Done preparing exe for dumping");

    exe_log();
}

/* We set things up so that calling the OEP raises an exception which is
   handled here. */
static LONG WINAPI dump(EXCEPTION_POINTERS* ex_pointers)
{
    log_debug("Entered OEP hook: eip %p, exception code %X", 
        ex_pointers->ContextRecord->Eip, 
        ex_pointers->ExceptionRecord->ExceptionCode);
    
    if (ex_pointers->ExceptionRecord->ExceptionCode != 
            STATUS_GUARD_PAGE_VIOLATION) {
        log_warn("Exception handler triggered with non guard page violation "
            "code");
    }

    /* Revert protection to avoid further failures */
    set_guard_state(false);

    exe_log();

    /* Cleanup some stuff introduced by htpec */
    prepare_for_dumping(ex_pointers->ContextRecord->Eip);

    exe_log();
    import_cache_log();

    iat_find_iats();
    iat_log();

    exe_emit_import_descriptors(iat_get_found_iats());

    exe_log();

    exe_dump_to_file("dump.exe");

    ExitProcess(0);
    //return EXCEPTION_CONTINUE_EXECUTION;
}

/* ========================================================================== */

char* kernal32_CreateFileAHook(char* lpFileName)
{
    char exeFileName[MAX_PATH];
    char* pos;

    GetModuleFileNameA(NULL, exeFileName, MAX_PATH);

    if (!_stricmp(lpFileName, exeFileName)) {
        pos = exeFileName + strlen(exeFileName) - 3;
        strcpy(pos, "bak");

        log_debug("Diverted read to .bak file: %s", exeFileName);

        return util_str_dup(exeFileName);
    } else {
        return NULL;
    }
}

static bool arm_handler = false;

void kernal32_SetLastErrorHook(DWORD code)
{
    static int nCalls = 0;

    /* The fourth call to this proc is made immediately before HtPec
       jumps to the OEP. */

    log_info("SetLastError call count: %d", ++nCalls);

    if (nCalls == 4) {
        exe_log();
        /* Protect the original entry point to trigger the exception handler */
        if (arm_handler) {
            set_guard_state(true);
            SetUnhandledExceptionFilter(dump);
            
            log_info("Inserted OEP hook");
        }
    }
}

/* ========================================================================== */

HMODULE WINAPI kernal32_GetModuleHandleA(const char* name)
{
    log_debug("GetModuleHandleA: %s", name);

    HMODULE module = GetModuleHandleA(name);

    if (name && module) {
        /* Collect dlls */
        import_cache_add_dll(module, name);
    } 

    log_debug("GetModuleHandleA: %s -> %p", name, module);

    if (name && !strcmp("KeRnEl32.dLl", name)) {
        log_info("Arm exception handler trap for dumping");
        arm_handler = true;
    }

    return module;
}

HMODULE WINAPI kernal32_LoadLibraryA(const char* name)
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

BOOL WINAPI kernal32_GetVersionExA(OSVERSIONINFOA* ver)
{
    log_debug("GetVersionExA");

    return GetVersionExA(ver);
}

void* WINAPI kernal32_GetProcAddress(HMODULE module, const char* param)
{
    if (!HIWORD(param)) {
        /* By ordinal */

        uint16_t ordinal = LOWORD(param);

        log_debug("GetProcAddress (ordinal): %p, %d", module, ordinal);

        void* proc = GetProcAddress(module, param);

        log_debug("GetProcAddress (ordinal): %p, %d -> %p", module, ordinal, 
            proc);

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

        log_debug("GetProcAddress (name): %p, %s -> %p", module, param, 
            orig_proc);

        if (!orig_proc) {
            log_warn("GetProcAddress: name %s of module %p failed to resolve",
                param, module);
        }

        /* Detour if on list */
        if (proc_detour) {
            if (!_stricmp(param, "NtQuerySystemInformation")) {
                func_NtQuerySystemInformation = orig_proc;
            } else if (!_stricmp(param, "DbgUiRemoteBreakin")) {
                func_DbgUiRemoteBreakin = orig_proc;
            }

            /* Use the detour because htpac uses GetProcAddress to assemble
               the IAT. If we return the address of a detour func, we have
               to cache this to resolve it correctly later on when scanning
               and analyzing the IATs */
            import_cache_add_import_by_name(module, proc_detour, param);

            return proc_detour;
        } else {
            /* Collect imports */
            import_cache_add_import_by_name(module, orig_proc, param);

            return orig_proc;
        }
    }
}

/* ========================================================================== */

BOOL WINAPI DllMain(HMODULE hSelf, DWORD reason, CONTEXT* pInitContext)
{
    if (reason == DLL_PROCESS_ATTACH && !initialized) {
        initialized = true;

        char buffer[512];

        /* htpac spawns multiple processes for his unpacking stages. ensure
           the log files aren't overwritten to get a full trace of all spawned
           processes */
        sprintf(buffer, "kernal32.log.%ld", GetTickCount());

        util_log_set_file(buffer);
        log_info("Init");
        log_info("Current process id: %d", GetProcessId(GetCurrentProcess()));

        exe_init(GetModuleHandleA(NULL));

        exe_log();
    }

    return TRUE;
}

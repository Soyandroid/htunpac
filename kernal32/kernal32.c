#define LOG_MODULE "kernal32"

#include <stdbool.h>
#include <windows.h>

#include "util/log.h"

static bool initialized = false;

HMODULE WINAPI my_GetModuleHandleA(const char* name)
{
    log_debug("GetModuleHandleA: %s", name);

    HMODULE module = GetModuleHandleA(name);

    log_debug("GetModuleHandleA: %s -> %p", name, module);

    return module;
}

HMODULE WINAPI my_LoadLibraryA(const char* name)
{
    log_debug("LoadLibraryA: %s", name);

    HMODULE module = LoadLibraryA(name);

    log_debug("LoadLibraryA: %s -> %p", module);

    return module;
}

BOOL WINAPI my_GetVersionExA(OSVERSIONINFOA* ver)
{
    log_debug("GetVersionExA");

    return GetVersionExA(ver);
}

void* WINAPI my_GetProcAddress(HMODULE module, const char* param)
{
    log_debug("GetProcAddress: %p, %s", module, param);

    void* ptr = GetProcAddress(module, param);

    log_debug("GetProcAddress: %p, %s -> %p", module, param, ptr);

    return ptr;
}

BOOL WINAPI DllMain(HMODULE hSelf, DWORD reason, CONTEXT* pInitContext)
{
    if (reason == DLL_PROCESS_ATTACH && !initialized) {
        initialized = true;
        util_log_set_file("kernal32.log");
        log_info("Init");
    }

    return TRUE;
}

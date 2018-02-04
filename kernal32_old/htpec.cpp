/* insert pretentious morpheus "what is real" speech here */

#include "stdafx.h"
#include "dump.h"
#include "exe.h"
#include "imports.h"
#include "log.h"

struct DETOUR
{
    const char *name;
    void *proc;
};

static ATL::CAutoPtr<CExecutable> g_pExe;
static CImportCache g_imports;

void * WINAPI FakeGetProcAddress(HMODULE hModule, const char *param);

static void SetGuardState(BOOL on)
{
    DWORD old;
    int i;

    log_debug("Setting guard page state: %d", on);

    for (i = 0 ; i < g_pExe->GetSectionCount() - 2 ; i++)
    {
        const IMAGE_SECTION_HEADER *pSec = g_pExe->GetSection(i);
        VirtualProtect(g_pExe->FromRva<BYTE>(pSec->VirtualAddress), 
            pSec->Misc.VirtualSize, PAGE_READWRITE | (-on & PAGE_GUARD), &old);
    }
}

static void FixUpHeaders(DWORD oep)
{
    IMAGE_NT_HEADERS *pHeaders = g_pExe->GetNtHeaders();

    log_debug("Entering FixUpHeaders");

    // Kill HTPEC shit
    g_pExe->DeleteSection(g_pExe->GetSectionCount() - 1);
    g_pExe->DeleteSection(g_pExe->GetSectionCount() - 1);
    log_debug("    Killed HtPec sections");

    // Restore OEP
    pHeaders->OptionalHeader.AddressOfEntryPoint = g_pExe->ToRva(oep);
    log_debug("    Restored OEP: %p", pHeaders->OptionalHeader.AddressOfEntryPoint);

    // Nuke all data directories
    ZeroMemory(pHeaders->OptionalHeader.DataDirectory,
        sizeof(IMAGE_DATA_DIRECTORY) * 16);
    log_debug("    Clearing image data directory");

    // Trim off any BSS, enable writeability
    // (If the section containing the IATs is read-only, the EXE will crash
    // early on in the bootstrapping process).
    for (size_t i = 0 ; i < g_pExe->GetSectionCount() ; i++)
    {
        IMAGE_SECTION_HEADER *pSec = g_pExe->GetSection(i);
        BYTE *pBottom = g_pExe->FromRva<BYTE>(pSec->VirtualAddress);
        BYTE *pTop = pBottom + pSec->Misc.VirtualSize - 1;

        while (pTop > pBottom && !*pTop)
        {
            pTop--;
        }

        pSec->SizeOfRawData = pTop - pBottom + 1;
        pSec->Characteristics |= IMAGE_SCN_MEM_WRITE;

        log_debug("    BSS fix and write enable for section #%d", i);
    }

    log_debug("Leaving FixUpHeaders");
}

// We set things up so that calling the OEP raises an exception which is
// handled here.
static LONG WINAPI DumpEXE(EXCEPTION_POINTERS *pExPointers)
{
    log_debug("Entered OEP hook: eip %p", pExPointers->ContextRecord->Eip);

    SetGuardState(FALSE);
    FixUpHeaders(pExPointers->ContextRecord->Eip);
    DumpExe(g_pExe, &g_imports, "dump.exe");

    ExitProcess(0);
}

HMODULE WINAPI FakeGetModuleHandleA(const char *name)
{
    HMODULE hModule = GetModuleHandleA(name);

    if (name && hModule)
    {
        ATL::CString upper(name);
        g_imports.TouchDLL(hModule, upper.MakeUpper());
    }

    return hModule;
}

HMODULE WINAPI FakeLoadLibraryA(const char *name)
{
    HMODULE hModule = LoadLibraryA(name);

    if (!hModule)
    {
        log_debug("%s: DLL not found!", name);
    }
    else
    {
        ATL::CString upper(name);
        g_imports.TouchDLL(hModule, upper.MakeUpper());
    }

    return hModule;
}

BOOL WINAPI FakeGetVersionExA(OSVERSIONINFOA *ver)
{
	static int count = 0;

	log_debug("FakeGetVersionExA: %d", ver->dwOSVersionInfoSize);

	if (++count == 4) 
	{
		
	}

    return GetVersionExA(ver);
}

BOOL WINAPI FakeIsDebuggerPresent(void)
{
	log_debug("FakeIsDebuggerPresent");
	return FALSE;
}

BOOL WINAPI FakeCheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
	log_debug("FakeCheckRemoteDebuggerPresent");
	*pbDebuggerPresent = FALSE;
	return TRUE;
}

static HANDLE WINAPI FakeCreateFileA(char *lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile)
{
    HANDLE hFile;
    char exeFileName[MAX_PATH];
    char *pos;

    log_debug("CreateFileA: %s", lpFileName);

    GetModuleFileNameA(NULL, exeFileName, MAX_PATH);

    if (_stricmp(lpFileName, exeFileName) == 0)
    {
        pos = exeFileName + strlen(exeFileName) - 3;
        strcpy(pos, "bak");

        log_debug("Diverted read to .bak file: %s", exeFileName);
        lpFileName = exeFileName;
    }

    hFile = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
        hTemplateFile);

    return hFile;
}

static void WINAPI FakeSetLastError(DWORD code)
{
    static int nCalls = 0;

    // The fourth call to this proc is made immediately before HtPec
    // jumps to the OEP.

    log_debug("SetLastError call count: %d", ++nCalls);

    if (nCalls == 4)
    {
       	SetGuardState(TRUE);
        SetUnhandledExceptionFilter(DumpEXE);

        log_debug("Inserted OEP hook");
    }

    SetLastError(code);
}

static BOOL WINAPI FakeQueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
	log_debug("FakeQueryPerformanceCounter");

	SetGuardState(TRUE);
    SetUnhandledExceptionFilter(DumpEXE);

    log_debug("Inserted OEP hook");

	lpPerformanceCount->LowPart = 0;
	lpPerformanceCount->HighPart = 0;
	return TRUE;
}

static BOOL WINAPI FakeQueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
	log_debug("FakeQueryPerformanceFrequency");

	lpFrequency->LowPart = 0;
	lpFrequency->HighPart = 0;
	return TRUE;
}

static void *GetProcByOrdinal(HMODULE hModule, WORD ordinal)
{
    // Import by ordinal
    void *pProc = GetProcAddress(hModule, (char *) ordinal);

    if (!pProc)
    {
        log_debug("Ordinal #%d from some DLL failed to resolve!");
    }
    else
    {
        g_imports.TouchImportOrdinal(hModule, pProc, ordinal);
    }

    return pProc;
}

static void *GetProcByName(HMODULE hModule, const char *impName)
{
    static DETOUR detours[] =
    {
        { "GetModuleHandleA",       FakeGetModuleHandleA },
        { "LoadLibraryA",           FakeLoadLibraryA },
        { "GetProcAddress",         FakeGetProcAddress },
		{ "GetVersionExA",         FakeGetVersionExA },
//		{ "IsDebuggerPresent", FakeIsDebuggerPresent },
//		{ "CheckRemoteDebuggerPresent", FakeCheckRemoteDebuggerPresent },
        { "CreateFileA",            FakeCreateFileA },
        { "SetLastError",           FakeSetLastError },
		{ "QueryPerformanceCounter", FakeQueryPerformanceCounter},
		{ "QueryPerformanceFrequency", FakeQueryPerformanceFrequency},
        { NULL, NULL }
    };

    const DETOUR *pDetour;
    void *pProc;

    for (pDetour = detours ; pDetour->name ; pDetour++)
    {
        if (strcmp(pDetour->name, impName) == 0)
        {
            pProc = pDetour->proc;
            break;
        }
    }

    if (!pDetour->name)
    {
        pProc = GetProcAddress(hModule, impName);
    }

	if (!strcmp("InitializeCriticalSectionAndSpinCount", impName)) 
	{

	}

    if (!pProc)
    {
        log_debug("%s: Not resolved!!", impName);
    }
    else
    {
        g_imports.TouchImportName(hModule, pProc, impName);
    }

    return pProc;
}

void * WINAPI FakeGetProcAddress(HMODULE hModule, const char *param)
{
	//log_debug("FakeGetProcAddress: %p %s", hModule, param);

    if (!HIWORD(param))
    {
        return GetProcByOrdinal(hModule, LOWORD(param));
    }
    else
    {
        return GetProcByName(hModule, param);
    }
}

BOOL WINAPI DllMain(HMODULE hSelf, DWORD reason, CONTEXT *pInitContext)
{
    if (reason == DLL_PROCESS_ATTACH && pInitContext != NULL)
    {
		util_log_set_file("kernal32.log");
        g_pExe.Attach( new CExecutable(GetModuleHandleA(NULL)) );
    }

    return TRUE;
}

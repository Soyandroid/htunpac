#define LOG_MODULE "monitor"

#include "kernal32/monitor.h"
#include "kernal32/kernal32.h"

#include "util/log.h"

NTSTATUS WINAPI (*func_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength) = NULL;

void NTAPI (*func_DbgUiRemoteBreakin)() = NULL;

HANDLE WINAPI mon_CreateFileA(char* lpFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, 
        HANDLE hTemplateFile)
{
    log_debug("CreateFileA: %s %X %X %X %X", lpFileName, dwDesiredAccess, 
        dwShareMode, dwCreationDisposition, dwFlagsAndAttributes);

    char* detour = kernal32_CreateFileAHook(lpFileName);

    if (detour) {
        lpFileName = detour;
    }

    HANDLE handle = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
        hTemplateFile);

    log_debug("CreatFileA: %s -> %p", lpFileName, handle);
    
    if (detour) {
        free(detour);
    }

    return handle;
}

BOOL WINAPI mon_WriteFile(HANDLE hFile, LPCVOID lpBuffer, 
        DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, 
        LPOVERLAPPED lpOverlapped)
{
    log_debug("WriteFile: %p %p %d", hFile, lpBuffer, nNumberOfBytesToWrite);

    BOOL ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, 
        lpNumberOfBytesWritten, lpOverlapped);

    log_debug("WriteFile: %p -> %d", hFile, ret);

    return ret;
}

BOOL WINAPI mon_ReadFile(HANDLE hFile, LPVOID lpBuffer, 
        DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, 
        LPOVERLAPPED lpOverlapped)
{
    log_debug("ReadFile: %p %p %d", hFile, lpBuffer, nNumberOfBytesToRead);

    BOOL ret = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, 
        lpNumberOfBytesRead, lpOverlapped);

    log_debug("ReadFile: %p -> %d", hFile, ret);

    return ret;
}

BOOL WINAPI mon_DeleteFileA(LPCSTR lpFileName)
{
    log_debug("DeleteFileA: %s", lpFileName);

    BOOL ret = DeleteFileA(lpFileName);

    log_debug("DeleteFileA: %s -> %d", lpFileName, ret);

    return ret;
}

UINT WINAPI mon_GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, 
        UINT uUnique, LPSTR lpTempFileName)
{
    log_debug("GetTempFileNameA: %s %s %d %s", lpPathName, lpPrefixString, 
        uUnique, lpTempFileName);
    
    UINT ret = GetTempFileNameA(lpPathName, lpPrefixString, uUnique, 
        lpTempFileName);

    log_debug("GetTempFileNameA: %s -> %d", lpPathName, ret);

    return ret;
}

DWORD WINAPI mon_GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)
{
    log_debug("GetTempPathA: %d %p", nBufferLength, lpBuffer);

    DWORD ret = GetTempPathA(nBufferLength, lpBuffer);

    log_debug("GetTempPathA: %d -> %s %d", nBufferLength, lpBuffer, ret);

    return ret;
}

DWORD WINAPI mon_SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
        PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    log_debug("SetFilePointer: %p %d %d %d", hFile, lDistanceToMove, 
        lpDistanceToMoveHigh, dwMoveMethod);

    DWORD ret = SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, 
        dwMoveMethod);

    log_debug("SetFilePointer: %p -> %d", hFile, ret);

    return ret;
}

BOOL WINAPI mon_CloseHandle(HANDLE hObject)
{
    log_debug("CloseHandle: %p", hObject);

    BOOL ret = CloseHandle(hObject);

    log_debug("CloseHandle: %p -> %d", hObject, ret);

    return ret;
}

BOOL WINAPI mon_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, 
        DWORD flNewProtect, PDWORD lpflOldProtect)
{
    log_debug("VirtualProtect: %p %d %X (%s)", lpAddress, dwSize, flNewProtect, 
        flNewProtect & PAGE_GUARD ? "GUARDED PAGE" : "no guard");

    BOOL ret = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    log_debug("VirtualProtect: %p -> %X %d", lpAddress, lpflOldProtect, ret);

    return ret;
}

BOOL WINAPI mon_Beep(DWORD dwFreq, DWORD dwDuration)
{
    log_debug("Beep: %d %d", dwFreq, dwDuration);

    BOOL ret = Beep(dwFreq, dwDuration);

    log_debug("Beep: %d %d -> %d", dwFreq, dwDuration, ret);

    return ret;
}

HANDLE WINAPI mon_GetCurrentProcess(void)
{
    log_debug("GetCurrentProcess");

    HANDLE ret = GetCurrentProcess();

    log_debug("GetCurrentProcess -> %p", ret);

    return ret;
}

DWORD WINAPI mon_GetCurrentProcessId(void)
{
    log_debug("GetCurrentProcessId");

    DWORD ret = GetCurrentProcessId();

    log_debug("GetCurrentProcessId -> %d", ret);

    return ret;
}

DWORD WINAPI mon_GetTickCount(void)
{
    log_debug("GetTickCount");

    DWORD ret = GetTickCount();

    log_debug("GetTickCount -> %d", ret);

    return ret;
}

BOOL WINAPI mon_SystemTimeToFileTime(const SYSTEMTIME* lpSystemTime, 
        LPFILETIME lpFileTime)
{
    log_debug("SystemTimeToFileTime");

    BOOL ret = SystemTimeToFileTime(lpSystemTime, lpFileTime);

    log_debug("SystemTimeToFileTime -> %d", ret);

    return ret;
}

void WINAPI mon_GetLocalTime(LPSYSTEMTIME lpSystemTime)
{
    log_debug("GetLocalTime");

    GetLocalTime(lpSystemTime);
}

BOOL WINAPI mon_IsDebuggerPresent(void)
{
    log_debug("IsDebuggerPresent");

    BOOL ret = IsDebuggerPresent();

    log_debug("IsDebuggerPresent -> %d", ret);

    return ret;
}

BOOL WINAPI mon_CheckRemoteDebuggerPresent(HANDLE hProcess, 
        PBOOL pbDebuggerPresent)
{
    log_debug("CheckRemoteDebuggerPresent: %p", hProcess);

    BOOL ret = CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);

    log_debug("CheckRemoteDebuggerPresent: %p -> %d %d", hProcess, 
        *pbDebuggerPresent, ret);

    return ret;
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI mon_SetUnhandledExceptionFilter(
        LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    log_debug("SetUnhandledExceptionFilter: %p", lpTopLevelExceptionFilter);

    LPTOP_LEVEL_EXCEPTION_FILTER ret = SetUnhandledExceptionFilter(
        lpTopLevelExceptionFilter);

    log_debug("SetUnhandledExceptionFilter: %p -> %p", 
        lpTopLevelExceptionFilter, ret);

    return ret;
}

LONG WINAPI mon_UnhandledExceptionFilter(
        struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    log_debug("UnhandledExceptionFilter: %p", ExceptionInfo);

    LONG ret = UnhandledExceptionFilter(ExceptionInfo);

    log_debug("UnhandledExceptionFilter: %p -> %d", ExceptionInfo, ret);

    return ret;
}

void WINAPI mon_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    log_debug("GetSystemInfo");

    GetSystemInfo(lpSystemInfo);
}

BOOL WINAPI mon_GetProcessAffinityMask(HANDLE hProcess, 
        PDWORD_PTR lpProcessAffinityMask, PDWORD_PTR lpSystemAffinityMask)
{
    log_debug("GetProcessAffinityMask: %p", hProcess);

    BOOL ret = GetProcessAffinityMask(hProcess, lpProcessAffinityMask, 
        lpSystemAffinityMask);

    log_debug("GetProcessAffinityMask: %p -> %X %X %d", hProcess, 
        *lpProcessAffinityMask, *lpSystemAffinityMask, ret);

    return ret; 
}

BOOL WINAPI mon_SetProcessAffinityMask(HANDLE hProcess, 
        DWORD_PTR dwProcessAffinityMask)
{
    log_debug("SetProcessAffinityMask: %p %X", hProcess, dwProcessAffinityMask);

    BOOL ret = SetProcessAffinityMask(hProcess, dwProcessAffinityMask);

    log_debug("SetProcessAffinityMask: %p -> %d", hProcess, ret);

    return ret; 
}

BOOL WINAPI mon_UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    log_debug("UnmapViewOfFile: %p", lpBaseAddress);

    BOOL ret = UnmapViewOfFile(lpBaseAddress);

    log_debug("UnmapViewOfFile: %p -> %d", lpBaseAddress, ret);

    return ret;
}

VOID WINAPI mon_ExitProcess(UINT uExitCode)
{
    log_debug("ExitProcess: %d", uExitCode);

    ExitProcess(uExitCode);
}

void WINAPI mon_SetLastError(DWORD code)
{
    log_debug("SetLastError: %d", code);

    kernal32_SetLastErrorHook(code);

    SetLastError(code);
}

void NTAPI mon_DbgUiRemoteBreakin()
{
    log_debug("DbgUiRemoteBreakin");

    func_DbgUiRemoteBreakin();
}

HANDLE WINAPI mon_GetProcessHeap(void)
{
    log_debug("GetProcessHeap");

    HANDLE ret = GetProcessHeap();

    log_debug("GetProcessHeap: -> %p", ret);

    return ret;
}

LPVOID WINAPI mon_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    log_debug("HeapAlloc: %p %X %d", hHeap, dwFlags, dwBytes);

    LPVOID ret = HeapAlloc(hHeap, dwFlags, dwBytes);

    log_debug("HeapAlloc: %p -> %p", hHeap, ret);

    return ret;
}

BOOL WINAPI mon_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    log_debug("HeapFree: %p %X %p", hHeap, dwFlags, lpMem);

    BOOL ret = HeapFree(hHeap, dwFlags, lpMem);

    log_debug("HeapFree: %p -> %d", hHeap, ret);

    return ret;
}

BOOL WINAPI mon_GetKernelObjectSecurity(HANDLE Handle, 
    SECURITY_INFORMATION RequestedInformation, 
    PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, 
    LPDWORD lpnLengthNeeded)
{
    log_debug("GetKernelObjectSecurity: %p %p %p %d %d", Handle, 
        RequestedInformation, pSecurityDescriptor, nLength, *lpnLengthNeeded);

    BOOL ret = GetKernelObjectSecurity(Handle, RequestedInformation, 
        pSecurityDescriptor, nLength, lpnLengthNeeded);

    log_debug("GetKernelObjectSecurity: %p -> %d", Handle, ret);

    return ret;
}

BOOL WINAPI mon_GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
    LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted)
{
    log_debug("GetSecurityDescriptorDacl: %p", pSecurityDescriptor);

    BOOL ret = GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, 
        pDacl, lpbDaclDefaulted);

    log_debug("GetSecurityDescriptorDacl: %p -> %d", pSecurityDescriptor, ret);

    return ret;
}

BOOL WINAPI mon_GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce)
{
    log_debug("GetAce: %p, %d %p", pAcl, dwAceIndex, pAce);

    BOOL ret = GetAce(pAcl, dwAceIndex, pAce);

    log_debug("GetAce: %p -> %d", pAcl, ret);

    return ret;
}

BOOL WINAPI mon_SetKernelObjectSecurity(HANDLE Handle, 
    SECURITY_INFORMATION SecurityInformation, 
    PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    log_debug("SetKernelObjectSecurity: %p", Handle);

    BOOL ret = SetKernelObjectSecurity(Handle, SecurityInformation, 
        SecurityDescriptor);

    log_debug("SetKernelObjectSecurity: %p -> %d", Handle, ret);

    return ret;
}

DWORD WINAPI mon_GetModuleFileName(HMODULE hModule, LPTSTR lpFilename, DWORD nSize)
{
    log_debug("GetModuleFileName: %p %d", hModule, nSize);

    DWORD ret = GetModuleFileName(hModule, lpFilename, nSize);

    log_debug("GetModuleFileName: %p %d -> %s %d", hModule, nSize, lpFilename, 
        ret);

    return ret;
}

DWORD WINAPI mon_GetLastError(void)
{
    log_debug("GetLastError");

    DWORD ret = GetLastError();

    log_debug("GetLastError: %d", ret);

    return ret;
}

UINT WINAPI mon_SetErrorMode(UINT uMode)
{
    log_debug("SetErrorMode: %d", uMode);

    UINT ret = SetErrorMode(uMode);

    log_debug("SetErrorMode: %d -> %d", uMode, ret);

    return ret;
}

BOOL WINAPI mon_FreeLibrary(HMODULE hModule)
{
    log_debug("FreeLibrary: %p", hModule);

    BOOL ret = FreeLibrary(hModule);

    log_debug("FreeLibrary: %p -> %d", hModule, ret);

    return ret;
}

VOID WINAPI mon_Sleep(DWORD dwMilliseconds)
{
    log_debug("Sleep: %d", dwMilliseconds);

    Sleep(dwMilliseconds);   
}

LONG WINAPI mon_RegQueryValueEx(HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    log_debug("RegQueryValueEx: %p %s %d", hKey, lpValueName, lpType);

    LONG ret = RegQueryValueEx(hKey, lpValueName, lpReserved, lpType, lpData, 
        lpcbData);

    log_debug("RegQueryValueEx: %p -> %d", hKey, ret);

    return ret;
}

LONG WINAPI mon_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    log_debug("RegSetValueEx: %p %s %d", hKey, lpValueName, dwType);

    LONG ret = RegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, 
        cbData);

    log_debug("RegSetValueEx: %p -> %d", hKey, ret);

    return ret;
}

LONG WINAPI mon_RegCloseKey(HKEY hKey)
{
    log_debug("RegCloseKey: %p", hKey);

    LONG ret = RegCloseKey(hKey);

    log_debug("RegCloseKey: %p -> %d", hKey, ret);

    return ret;
}

LONG WINAPI mon_RegOpenKeyEx(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions,
    REGSAM samDesired, PHKEY phkResult)
{
    log_debug("RegOpenKeyEx: %p %s %d", hKey, lpSubKey, ulOptions);

    LONG ret = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    log_debug("RegOpenKeyEx: %p -> %d", hKey, ret);

    return ret;
}

NTSTATUS WINAPI mon_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    log_debug("NtQuerySystemInformation: %d", SystemInformationClass);

    NTSTATUS ret = func_NtQuerySystemInformation(SystemInformationClass, 
        SystemInformation, SystemInformationLength, ReturnLength);

    log_debug("NtQuerySystemInformation: %d -> %d", SystemInformationClass, 
        ret);

    return ret;
}

DWORD WINAPI mon_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    log_debug("GetFileSize: %p", hFile);

    DWORD ret = GetFileSize(hFile, lpFileSizeHigh);

    log_debug("GetFileSize: %p -> %d %d", hFile, ret, 
        lpFileSizeHigh ? *lpFileSizeHigh : 0);

    return ret;
}

LPVOID WINAPI mon_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, 
    DWORD flAllocationType, DWORD flProtect)
{
    log_debug("VirtualAlloc: %p %d %X %X", lpAddress, dwSize, flAllocationType, 
        flProtect);

    LPVOID ret = VirtualAlloc(lpAddress, dwSize, flAllocationType, 
        flProtect);

    log_debug("VirtualAlloc: %p -> %p", lpAddress, ret);

    return ret;
}

BOOL WINAPI mon_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    log_debug("VirtualFree: %p %d %d", lpAddress, dwSize, dwFreeType);

    BOOL ret = VirtualFree(lpAddress, dwSize, dwFreeType);

    log_debug("VirtualFree: %p -> %d", lpAddress, ret);

    return ret;
}

BOOL WINAPI mon_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode,
    LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, 
    DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    log_debug("DeviceIoControl: %p %X %p %d %p %d", hDevice, dwIoControlCode, 
        lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize);

    BOOL ret = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, 
        nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, 
        lpOverlapped);

    log_debug("DeviceIoControl: %p -> %d %d", hDevice, *lpBytesReturned, ret);

    return ret;
}

UINT WINAPI mon_GetWindowsDirectory(LPTSTR lpBuffer, UINT uSize)
{
    log_debug("GetWindowsDirectory: %p %d", lpBuffer, uSize);

    UINT ret = GetWindowsDirectory(lpBuffer, uSize);

    log_debug("GetWindowsDirectory: %p -> %d", lpBuffer, ret);

    return ret;
}

DWORD WINAPI mon_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    log_debug("WaitForSingleObject: %p %d", hHandle, dwMilliseconds);

    DWORD ret = WaitForSingleObject(hHandle, dwMilliseconds);

    log_debug("WaitForSingleObject: %p -> %d", hHandle, ret);

    return ret;
}

HANDLE WINAPI mon_CreateMutex(LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL bInitialOwner, LPCTSTR lpName)
{
    log_debug("CreateMutex: %p %d %s", lpMutexAttributes, bInitialOwner, 
        lpName);

    HANDLE ret = CreateMutex(lpMutexAttributes, bInitialOwner, 
        lpName);

    log_debug("CreateMutex: %p -> %p", lpMutexAttributes, lpName);

    return ret;
}

BOOL WINAPI mon_ReleaseMutex(HANDLE hMutex)
{
    log_debug("ReleaseMutex: %p", hMutex);

    BOOL ret = ReleaseMutex(hMutex);

    log_debug("ReleaseMutex: %p -> %d", hMutex, ret);

    return ret;
}

void WINAPI mon_RtlUnwind(PVOID TargetFrame, PVOID TargetIp, 
    PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
{
    log_debug("RtlUnwind: %p %p %p", TargetFrame, TargetIp, ExceptionRecord);

    RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue);

    log_debug("RtlUnwind: %p -> %p", TargetFrame, ReturnValue);
}

LPVOID WINAPI mon_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
        DWORD flAllocationType, DWORD flProtect)
{
    log_debug("VirtualAllocEx: %p %p %d %d %d", hProcess, lpAddress, dwSize, 
        flAllocationType, flProtect);

    LPVOID ret = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, 
        flProtect);

    log_debug("VirtualAllocEx: %p -> %p", hProcess, ret);

    return ret;
}

int __cdecl mon_wsprintfA(LPTSTR lpOut, LPCTSTR lpFmt, ...)
{
    log_debug("wsprintfA: %s", lpFmt);

    va_list argptr;
    va_start(argptr, lpFmt);
    int ret = wvsprintfA(lpOut, lpFmt, argptr);
    va_end(argptr);
    
    log_debug("wsprintfA: %s -> %s %d", lpFmt, lpOut, ret);

    return ret;
}

int __cdecl mon_wsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, ...)
{
    log_debug("wsprintfW: %s", lpFmt);

    va_list argptr;
    va_start(argptr, lpFmt);
    int ret = wvsprintfW(lpOut, lpFmt, argptr);
    va_end(argptr);
    
    log_debug("wsprintfW: %s -> %s %d", lpFmt, lpOut, ret);

    return ret;
}

DWORD WINAPI mon_ResumeThread(HANDLE hThread)
{
    log_debug("ResumeThread: %p", hThread);

    DWORD ret = ResumeThread(hThread);

    log_debug("ResumeThread: %p -> %d", hThread, ret);

    return ret;
}

BOOL WINAPI mon_SetEvent(HANDLE hEvent)
{
    log_debug("SetEvent: %p", hEvent);

    BOOL ret = SetEvent(hEvent);

    log_debug("SetEvent: %p -> %d", hEvent, ret);

    return ret;
}

BOOL WINAPI mon_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    log_debug("GetThreadContext: %p", hThread);

    BOOL ret = GetThreadContext(hThread, lpContext);

    log_debug("GetThreadContext: %p -> %d", hThread, ret);

    return ret;
}

BOOL WINAPI mon_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, 
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    log_debug("WriteProcessMemory: %p %p %p %d", hProcess, lpBaseAddress, 
        lpBuffer, nSize);

    BOOL ret = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, 
        lpNumberOfBytesWritten);

    log_debug("WriteProcessMemory: %p %p -> %d", hProcess, lpBaseAddress,
        ret);

    return ret;
}

BOOL WINAPI mon_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect)
{
    log_debug("VirtualProtectEx: %p %p %d %d", hProcess, lpAddress, dwSize, 
        flNewProtect);

    BOOL ret = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, 
        lpflOldProtect);

    log_debug("VirtualProtectEx: %p %p -> %d", hProcess, lpAddress, ret);

    return ret;
}

BOOL WINAPI mon_CreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    log_debug("CreateProcessA: %s %s %p %p %d %X %p %s %p %p", 
        lpApplicationName, lpCommandLine, lpProcessAttributes, 
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, 
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    BOOL ret = CreateProcessA(lpApplicationName, lpCommandLine, 
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
        dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, 
        lpProcessInformation);

    log_debug("CreateProcessA: %s -> %d", lpApplicationName, ret);

    return ret;
}

BOOL WINAPI mon_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess,
    BOOL bInheritHandle, DWORD dwOptions)
{
    log_debug("DuplicateHandle: %p %p %p %p %d %d %d", hSourceProcessHandle, 
        hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess,
        bInheritHandle, dwOptions);

    BOOL ret = DuplicateHandle(hSourceProcessHandle, hSourceHandle, 
        hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, 
        dwOptions);

    log_debug("DuplicateHandle: %p %p -> %d", hSourceProcessHandle, 
        hSourceHandle, ret);

    return ret;
}

HANDLE WINAPI mon_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset, BOOL bInitialState, LPCTSTR lpName)
{
    log_debug("CreateEventA: %p %d %d %s", lpEventAttributes, bManualReset, 
        bInitialState, lpName);

    HANDLE ret = CreateEventA(lpEventAttributes, bManualReset, bInitialState, 
        lpName);

    log_debug("CreateEventA: %s -> %p", lpName, ret);

    return ret;
}

BOOL WINAPI mon_MoveFileA(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName)
{
    log_debug("MoveFileA: %s %s", lpExistingFileName, lpNewFileName);

    BOOL ret = MoveFileA(lpExistingFileName, lpNewFileName);

    log_debug("MoveFileA: %s %s -> %d", lpExistingFileName, lpNewFileName, ret);

    return ret;
}

HANDLE WINAPI mon_CreateFileMappingA(HANDLE hFile, 
    LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, 
    DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName)
{
    log_debug("CreateFileMappingA: %p %p %X %d %d %s", hFile, lpAttributes, 
        flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

    HANDLE ret = CreateFileMappingA(hFile, lpAttributes, flProtect, 
        dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

    log_debug("CreateFileMappingA: %p -> %p", hFile, ret);

    return ret;
}

BOOL WINAPI mon_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    log_debug("TerminateProcess: %p %d", hProcess, uExitCode);

    BOOL ret = TerminateProcess(hProcess, uExitCode);

    log_debug("TerminateProcess: %p -> %d", hProcess, ret);

    return ret;
}

BOOL WINAPI mon_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
    log_debug("ReadProcessMemory: %p %p %p %d", hProcess, lpBaseAddress, 
        lpBuffer, nSize);

    BOOL ret = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, 
        lpNumberOfBytesRead);

    log_debug("ReadProcessMemory: %p %p -> %d", hProcess, lpBaseAddress, ret);

    return ret;
}

LPTSTR WINAPI mon_GetCommandLineA(void)
{
    log_debug("GetCommandLineA");

    LPTSTR ret = GetCommandLineA();

    log_debug("GetCommandLineA: %s", ret);

    return ret;
}

HMODULE WINAPI mon_GetModuleHandleA(LPCTSTR lpModuleName)
{
    log_debug("GetModuleHandleA: %s", lpModuleName);

    HMODULE ret = GetModuleHandleA(lpModuleName);

    log_debug("GetModuleHandleA: %s -> %p", lpModuleName, ret);

    return ret;
}

DWORD WINAPI mon_GetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, 
    DWORD nSize)
{
    log_debug("GetModuleFileNameA: %p %s %d", hModule, lpFilename, nSize);

    DWORD ret = GetModuleFileNameA(hModule, lpFilename, nSize);

    log_debug("GetModuleFileNameA: %p %s -> %d", hModule, lpFilename, ret);

    return ret;
}

DWORD WINAPI mon_GetFullPathNameA(LPCTSTR lpFileName, DWORD nBufferLength,
    LPTSTR lpBuffer, LPTSTR *lpFilePart)
{
    log_debug("GetFullPathNameA: %s %d %p", lpFileName, nBufferLength, 
        lpBuffer);

    DWORD ret = GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, 
        lpFilePart);

    log_debug("GetFullPathNameA: %s -> %d", lpFileName, ret);

    return ret;
}

HGLOBAL WINAPI mon_GlobalFree(HGLOBAL hMem)
{
    log_debug("GlobalFree: %p", hMem);

    HGLOBAL ret = GlobalFree(hMem);

    log_debug("GlobalFree: %p -> %p", hMem, ret);

    return ret;
}

HGLOBAL WINAPI mon_GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    log_debug("GlobalAlloc: %d %d", uFlags, dwBytes);

    HGLOBAL ret = GlobalAlloc(uFlags, dwBytes);

    log_debug("GlobalAlloc: %d %d -> %p", uFlags, dwBytes, ret);

    return ret;   
}
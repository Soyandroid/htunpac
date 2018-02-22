#include <windows.h>
#include <winreg.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendedServiceTableInformation = 38,
    SystemPrioritySeparation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemThrottleNotificationInformation = 134,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemSpare0 = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    SystemManufacturingInformation = 157,
    SystemEnergyEstimationConfigInformation = 158,
    SystemHypervisorDetailInformation = 159,
    SystemProcessorCycleStatsInformation = 160,
    SystemVmGenerationCountInformation = 161,
    SystemTrustedPlatformModuleInformation = 162,
    SystemKernelDebuggerFlags = 163,
    SystemCodeIntegrityPolicyInformation = 164,
    SystemIsolatedUserModeInformation = 165,
    SystemHardwareSecurityTestInterfaceResultsInformation = 166,
    SystemSingleModuleInformation = 167,
    SystemAllowedCpuSetsInformation = 168,
    SystemDmaProtectionInformation = 169,
    SystemInterruptCpuSetsInformation = 170,
    SystemSecureBootPolicyFullInformation = 171,
    SystemCodeIntegrityPolicyFullInformation = 172,
    SystemAffinitizedInterruptProcessorInformation = 173,
    SystemRootSiloInformation = 174,
    SystemCpuSetInformation = 175,
    SystemCpuSetTagInformation = 176,
    MaxSystemInfoClass = 177,
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdrInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessConsoleHostProcess = 49,
    ProcessWindowInformation = 50,
    MaxProcessInfoClass    // always last one so no need to add a value manually
} PROCESSINFOCLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION;

extern NTSTATUS WINAPI (*func_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

extern void NTAPI (*func_DbgUiRemoteBreakin)();

HANDLE WINAPI mon_CreateFileA(char* lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile);

BOOL WINAPI mon_WriteFile(HANDLE hFile, LPCVOID lpBuffer, 
    DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, 
    LPOVERLAPPED lpOverlapped);

BOOL WINAPI mon_ReadFile(HANDLE hFile, LPVOID lpBuffer, 
    DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, 
    LPOVERLAPPED lpOverlapped);

BOOL WINAPI mon_DeleteFileA(LPCSTR lpFileName);

UINT WINAPI mon_GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, 
    UINT uUnique, LPSTR lpTempFileName);

DWORD WINAPI mon_GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);

DWORD WINAPI mon_SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

BOOL WINAPI mon_CloseHandle(HANDLE hObject);

BOOL WINAPI mon_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, 
    DWORD flNewProtect, PDWORD lpflOldProtect);

BOOL WINAPI mon_Beep(DWORD dwFreq, DWORD dwDuration);

HANDLE WINAPI mon_GetCurrentProcess(void);

DWORD WINAPI mon_GetCurrentProcessId(void);

DWORD WINAPI mon_GetTickCount(void);

BOOL WINAPI mon_SystemTimeToFileTime(const SYSTEMTIME* lpSystemTime, 
    LPFILETIME lpFileTime);

void WINAPI mon_GetLocalTime(LPSYSTEMTIME lpSystemTime);

BOOL WINAPI mon_IsDebuggerPresent(void);

BOOL WINAPI mon_CheckRemoteDebuggerPresent(HANDLE hProcess, 
    PBOOL pbDebuggerPresent);

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI mon_SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

LONG WINAPI mon_UnhandledExceptionFilter(
    struct _EXCEPTION_POINTERS* ExceptionInfo);

void WINAPI mon_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);

BOOL WINAPI mon_GetProcessAffinityMask(HANDLE hProcess, 
    PDWORD_PTR lpProcessAffinityMask, PDWORD_PTR lpSystemAffinityMask);

BOOL WINAPI mon_SetProcessAffinityMask(HANDLE hProcess, 
    DWORD_PTR dwProcessAffinityMask);

BOOL WINAPI mon_UnmapViewOfFile(LPCVOID lpBaseAddress);

VOID WINAPI mon_ExitProcess(UINT uExitCode);

void WINAPI mon_SetLastError(DWORD code);

void NTAPI mon_DbgUiRemoteBreakin();

HANDLE WINAPI mon_GetProcessHeap(void);

LPVOID WINAPI mon_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

BOOL WINAPI mon_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

BOOL WINAPI mon_GetKernelObjectSecurity(HANDLE Handle, 
    SECURITY_INFORMATION RequestedInformation, 
    PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, 
    LPDWORD lpnLengthNeeded);

BOOL WINAPI mon_GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
    LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);

BOOL WINAPI mon_GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);

BOOL WINAPI mon_SetKernelObjectSecurity(HANDLE Handle, 
    SECURITY_INFORMATION SecurityInformation, 
    PSECURITY_DESCRIPTOR SecurityDescriptor);

DWORD WINAPI mon_GetModuleFileName(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

DWORD WINAPI mon_GetLastError(void);

UINT WINAPI mon_SetErrorMode(UINT uMode);

BOOL WINAPI mon_FreeLibrary(HMODULE hModule);

VOID WINAPI mon_Sleep(DWORD dwMilliseconds);

LONG WINAPI mon_RegQueryValueEx(HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

LONG WINAPI mon_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE *lpData, DWORD cbData);

LONG WINAPI mon_RegCloseKey(HKEY hKey);

LONG WINAPI mon_RegOpenKeyEx(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions,
    REGSAM samDesired, PHKEY phkResult);

NTSTATUS WINAPI mon_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

DWORD WINAPI mon_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);

LPVOID WINAPI mon_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, 
    DWORD flAllocationType, DWORD flProtect);

BOOL WINAPI mon_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

BOOL WINAPI mon_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode,
    LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, 
    DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

UINT WINAPI mon_GetWindowsDirectory(LPTSTR lpBuffer, UINT uSize);

DWORD WINAPI mon_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

HANDLE WINAPI mon_CreateMutex(LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL bInitialOwner, LPCTSTR lpName);

BOOL WINAPI mon_ReleaseMutex(HANDLE hMutex);

void WINAPI mon_RtlUnwind(PVOID TargetFrame, PVOID TargetIp, 
    PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);

LPVOID WINAPI mon_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect);

int __cdecl mon_wsprintfA(LPTSTR lpOut, LPCTSTR lpFmt, ...);

int __cdecl mon_wsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, ...);

DWORD WINAPI mon_ResumeThread(HANDLE hThread);

BOOL WINAPI mon_SetEvent(HANDLE hEvent);

BOOL WINAPI mon_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);

BOOL WINAPI mon_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, 
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

BOOL WINAPI mon_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect);

BOOL WINAPI mon_CreateProcessA(LPCTSTR lpApplicationName,LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI mon_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess,
    BOOL bInheritHandle, DWORD dwOptions);

HANDLE WINAPI mon_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset, BOOL bInitialState, LPCTSTR lpName);

BOOL WINAPI mon_MoveFileA(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName);

HANDLE WINAPI mon_CreateFileMappingA(HANDLE hFile, 
    LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, 
    DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);

BOOL WINAPI mon_TerminateProcess(HANDLE hProcess, UINT uExitCode);

BOOL WINAPI mon_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

LPTSTR WINAPI mon_GetCommandLineA(void);

HMODULE WINAPI mon_GetModuleHandleA(LPCTSTR lpModuleName);

DWORD WINAPI mon_GetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, 
    DWORD nSize);

DWORD WINAPI mon_GetFullPathNameA(LPCTSTR lpFileName, DWORD nBufferLength,
    LPTSTR lpBuffer, LPTSTR *lpFilePart);

HGLOBAL WINAPI mon_GlobalFree(HGLOBAL hMem);

HGLOBAL WINAPI mon_GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
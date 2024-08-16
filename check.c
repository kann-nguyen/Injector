#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// Function prototypes
DWORD get_pid_by_name(const char *proc_name);
PVOID GetModuleBaseAddress(DWORD processID, const char* moduleName);

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

int main(void) {
    LPCSTR filename = "D:\\Workspace\\C++\\Injection\\test.exe";
    DWORD processID = get_pid_by_name("test.exe");

    if (processID == 0) {
        printf("Process not found.\n");
        return 1;
    }

    PVOID baseAddress = GetModuleBaseAddress(processID, filename);
    if (baseAddress != NULL) {
        printf("Base address of test.exe: 0x%p\n", baseAddress);

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processID);
        if (hProcess != NULL) {
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead)) {
                if (bytesRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    printf("DOS Header e_magic: 0x%x\n", dosHeader.e_magic);

                    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + dosHeader.e_lfanew);
                    IMAGE_NT_HEADERS ntHeaderData;
                    if (ReadProcessMemory(hProcess, ntHeader, &ntHeaderData, sizeof(ntHeaderData), &bytesRead)) {
                        if (bytesRead == sizeof(ntHeaderData)) {
                            printf("NT Headers Signature: 0x%x\n", ntHeaderData.OptionalHeader.SizeOfImage);

                            // Read entire image
                            SIZE_T imageSize = ntHeaderData.OptionalHeader.SizeOfImage;
                            BYTE *imageData = (BYTE *)malloc(imageSize);
                            if (imageData) {
                                if (ReadProcessMemory(hProcess, baseAddress, imageData, imageSize, &bytesRead)) {
                                    if (bytesRead == imageSize) {
                                        printf("Successfully read the entire image.\n");

                                        // Print the first 100 bytes of the image
                                        printf("First 100 bytes of the image:\n");
                                        for (SIZE_T i = 0; i < 100 && i < imageSize; i++) {
                                            printf("%02X ", imageData[i]);
                                            if ((i + 1) % 16 == 0) {
                                                printf("\n");
                                            }
                                        }
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
    } else {
        printf("Could not find the base address of test.exe.\n");
    }

    return 0;
}

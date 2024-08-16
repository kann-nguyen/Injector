#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

int PrintModules( DWORD processID )
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.
    printf( "\nProcess ID: %u\n", processID );

    // Get a handle to the process.
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if (NULL == hProcess)
        return 1;

   // Get a list of all the modules in this process.
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                _tprintf( TEXT("\t%s (0x%08X)\n"), szModName, hMods[i] );
            }
        }
    }

    // Release the handle to the process.
    CloseHandle( hProcess );

    return 0;
}

DWORD RunAndPauseProcess(LPCSTR exePath) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create the process
    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
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

int main(void)
{
    LPCSTR filename = "D:\\Workspace\\C++\\Injection\\test.exe";
    DWORD processID = get_pid_by_name("test.exe");

    if (processID == 0) {
        printf("Process not found.\n");
        return 1;
    }

    // Get the base address of "test.exe".
    PVOID baseAddress = GetModuleBaseAddress(processID, filename);

    if (baseAddress != NULL) {
        printf("Base address of test.exe: 0x%p\n", baseAddress);

        // Read the IMAGE_DOS_HEADER from the target process's memory
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

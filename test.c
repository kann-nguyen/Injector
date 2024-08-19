#include <windows.h>
#include <stdio.h>

DWORD InjectionEntryPoint(LPVOID lpParameter) {
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", MB_OK);
    return 0;
}


int main() {
    //Sleep(3000);
    //PVOID imageBase = GetModuleHandle(NULL);
    //PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    //PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    MessageBoxA(NULL, "Successfully!", "Main function in test.exe", MB_OK);
    //printf("%lx\n", (DWORD_PTR)main - (DWORD_PTR)imageBase);
    //printf("%lx\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
    return 0;
}



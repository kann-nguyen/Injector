#include <windows.h>
#include <stdio.h>

DWORD hehe(LPVOID lpParameter) {
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", MB_OK);
    return 0;
}

int main() {
    hehe(NULL);
    /*
    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    char message1[50];
    char message2[50];
    char message3[50];
    // Convert the imageBase (which is a pointer) to a hexadecimal string
    sprintf(message1, "Image Base: 0x%p", imageBase);
    sprintf(message2, "Dos Header: 0x%p", dosHeader);
    sprintf(message3, "Nt Header: 0x%p", ntHeader);


    // Display the image base address in a message box
    MessageBoxA(NULL, message1, "Image Base", MB_OK);
    MessageBoxA(NULL, message2, "Dos Header", MB_OK);
    MessageBoxA(NULL, message3, "Nt Header", MB_OK);
    while (1) {
    // Do nothing, just loop infinitely
    }

    */
    return 0;
}



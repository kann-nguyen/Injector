#include <windows.h>
#include <stdio.h>
#include <shlwapi.h> // For PathRemoveFileSpec and PathCombine

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
    const char* fileName = "test.exe"; // The name of the file you want to find

    // Get the full path of the file
    get_file_path_in_executable_dir(fileName, filePath, sizeof(filePath));

    // Print the result
    printf("Full path to %s: %s\n", fileName, filePath);

    return 0;
}

#include <stdio.h>
#include <windows.h>


// [LLM PASS]
// GOOD - 272
void example_1_good(void) {
    wchar_t * keyName = L"SOFTWARE\\TestKey";
    HKEY hKey;
    // FIX: Use HKEY_CURRENT_USER to respect the least privilege principle
    if (RegCreateKeyExW(
            HKEY_CURRENT_USER,
            keyName,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            NULL,
            &hKey,
            NULL) != ERROR_SUCCESS) {
        wprintf(L"Registry key could not be created\n");
    } else {
        wprintf(L"Registry key created successfully\n");
        RegCloseKey(hKey);
    }
}

// GOOD - 272
void example_2_good(void) {
    wchar_t * fileName = L"C:\\Users\\%USERNAME%\\Documents\\testfile.txt";
    HANDLE hFile;
    // FIX: OpenFile without FILE_FLAG_BACKUP_SEMANTICS to adhere to least privilege
    hFile = CreateFileW(
            fileName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"File could not be opened\n");
    } else {
        wprintf(L"File opened successfully\n");
        CloseHandle(hFile);
    }
}

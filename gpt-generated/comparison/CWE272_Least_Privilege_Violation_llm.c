#include <windows.h>
#include <stdio.h>


// [LLM PASS]
// BAD - 272
void example_1_bad(void) {
    wchar_t * keyName = L"SOFTWARE\\ExampleApp";
    HKEY hKey;
    // FLAW: Using HKEY_LOCAL_MACHINE grants more privileges than necessary
    if (RegCreateKeyW(
            HKEY_LOCAL_MACHINE,
            keyName,
            &hKey) != ERROR_SUCCESS) {
        wprintf(L"Failed to create registry key under HKLM\n");
    } else {
        wprintf(L"Registry key created under HKLM\n");
        RegCloseKey(hKey);
    }
}

// GOOD - 272
void example_1_good(void) {
    wchar_t * keyName = L"SOFTWARE\\ExampleApp";
    HKEY hKey;
    // FIX: Use HKEY_CURRENT_USER for access within the user's scope
    if (RegCreateKeyW(
            HKEY_CURRENT_USER,
            keyName,
            &hKey) != ERROR_SUCCESS) {
        wprintf(L"Failed to create registry key under HKCU\n");
    } else {
        wprintf(L"Registry key created under HKCU\n");
        RegCloseKey(hKey);
    }
}


// [LLM PASS]
// BAD - 272
void example_2_bad(void) {
    wchar_t * path = L"C:\\Windows\\System32\\example.txt";
    HANDLE hFile;
    // FLAW: Attempt to create a file in a privileged system directory
    hFile = CreateFileW(
                path,
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create file in C:\\Windows\\System32\\\n");
    } else {
        wprintf(L"File created in C:\\Windows\\System32\\\n");
        CloseHandle(hFile);
    }
}

// GOOD - 272
void example_2_good(void) {
    wchar_t * path = L"C:\\ExampleApp\\example.txt";
    HANDLE hFile;
    // FIX: Create a file in an application-specific directory
    hFile = CreateFileW(
                path,
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create file in C:\\ExampleApp\\\n");
    } else {
        wprintf(L"File created in C:\\ExampleApp\\\n");
        CloseHandle(hFile);
    }
}

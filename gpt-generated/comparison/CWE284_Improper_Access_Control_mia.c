#include <stdio.h>
#include <windows.h>


// [MIA PASS] Perplexity: 1.26
// BAD - 284
// This function improperly grants GENERIC_ALL access to a registry key, which can lead to privilege escalation.
void example_1_bad(void) {
    HKEY hKey;
    LPCWSTR subKey = L"SOFTWARE\\ExampleKey";

    // Attempt to open the registry key with full control.
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY | GENERIC_ALL, &hKey) != ERROR_SUCCESS) {
        wprintf(L"Failed to open registry key with GENERIC_ALL access.\n");
    } else {
        wprintf(L"Registry key opened with GENERIC_ALL access.\n");
        RegCloseKey(hKey);
    }
}

// GOOD - 284
// This function properly grants only the necessary access rights to a registry key.
void example_1_good(void) {
    HKEY hKey;
    LPCWSTR subKey = L"SOFTWARE\\ExampleKey";

    // Attempt to open the registry key with the least privilege needed: read access.
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        wprintf(L"Failed to open registry key with read access.\n");
    } else {
        wprintf(L"Registry key opened with read access.\n");
        RegCloseKey(hKey);
    }
}


// [MIA PASS] Perplexity: 1.13
// BAD - 284
// This function creates a file with excessive permissions, allowing unauthorized access.
void example_2_bad(void) {
    HANDLE hFile;
    LPCWSTR fileName = L"example.txt";

    // Create a file with full access rights to everyone.
    hFile = CreateFileW(
        fileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create or open file with GENERIC_ALL access.\n");
    } else {
        wprintf(L"File created or opened with GENERIC_ALL access.\n");
        CloseHandle(hFile);
    }
}

// GOOD - 284
// This function creates a file with restrictive permissions, preventing unauthorized access.
void example_2_good(void) {
    HANDLE hFile;
    LPCWSTR fileName = L"example.txt";

    // Create a file with read and write access but restrict sharing.
    hFile = CreateFileW(
        fileName,
        GENERIC_READ | GENERIC_WRITE,
        0, // No sharing
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create or open file with restrictive access.\n");
    } else {
        wprintf(L"File created or opened with restrictive access.\n");
        CloseHandle(hFile);
    }
}

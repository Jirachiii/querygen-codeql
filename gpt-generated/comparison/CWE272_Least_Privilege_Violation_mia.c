#include <windows.h>
#include <stdio.h>


// [MIA PASS] Perplexity: 1.15
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

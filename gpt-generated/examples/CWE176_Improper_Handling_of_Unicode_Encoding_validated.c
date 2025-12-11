#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <windows.h>

// BAD - CWE-176: Improper handling of Unicode encoding in file I/O operations
void fileReadBad() {
    // Open a file containing Unicode characters
    FILE *file = fopen("unicode.txt", "r");
    if (file) {
        wchar_t wtext[100];
        // Read unicode text from file
        fgetws(wtext, 100, file);
        fclose(file);

        char buffer[20]; // Small buffer
        // Convert unicode text to multibyte without checking size
        int bytes = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, buffer, sizeof(buffer), NULL, NULL);
        if (bytes == 0) {
            printf("Conversion failed\n");
        } else {
            printf("Converted text: %s\n", buffer);
        }
    }
}

// GOOD - Safe handling of Unicode encoding in file I/O operations
void fileReadGood() {
    // Open a file containing Unicode characters
    FILE *file = fopen("unicode.txt", "r");
    if (file) {
        wchar_t wtext[100];
        // Read unicode text from file
        fgetws(wtext, 100, file);
        fclose(file);

        // Determine the required size of the buffer
        int size = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
        if (size <= 0) {
            printf("Failed to get buffer size\n");
            return;
        }

        // Allocate adequately sized buffer
        char* buffer = (char*)malloc(size);
        if (buffer == NULL) {
            printf("Memory allocation failed\n");
            return;
        }

        // Convert unicode text to multibyte
        int bytes = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, buffer, size, NULL, NULL);
        if (bytes == 0) {
            printf("Conversion failed\n");
        } else {
            printf("Converted text: %s\n", buffer);
        }

        // Free buffer after use
        free(buffer);
    }
}

// BAD - CWE-176: Improper handling of Unicode encoding in network operations
void networkReceiveBad() {
    wchar_t wtext[100] = L"Received data example";  // Simulating network received data
    char dest[20];

    // Convert unicode string to multibyte without checking if dest is large enough
    int bytes = WideCharToMultiByte(CP_ACP, 0, wtext, -1, dest, sizeof(dest), NULL, NULL);
    if (bytes > 0) {
        printf("Converted text: %s\n", dest);
    } else {
        printf("Conversion failed\n");
    }
}

// GOOD - Safe handling of Unicode encoding in network operations
void networkReceiveGood() {
    wchar_t wtext[100] = L"Received data example";  // Simulating network received data

    // Get required size for destination buffer
    int size = WideCharToMultiByte(CP_ACP, 0, wtext, -1, NULL, 0, NULL, NULL);
    if (size <= 0) {
        printf("Failed to determine buffer size\n");
        return;
    }

    // Allocate buffer with sufficient size
    char* dest = (char*)malloc(size);
    if (dest == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    // Perform the conversion
    int bytes = WideCharToMultiByte(CP_ACP, 0, wtext, -1, dest, size, NULL, NULL);
    if (bytes > 0) {
        printf("Converted text: %s\n", dest);
    } else {
        printf("Conversion failed\n");
    }

    // Free allocated memory
    free(dest);
}

int main() {
    // Set locale for proper Unicode handling
    setlocale(LC_ALL, "");

    fileReadBad();
    fileReadGood();
    networkReceiveBad();
    networkReceiveGood();

    return 0;
}

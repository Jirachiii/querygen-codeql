#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <unistd.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#endif


// [LLM PASS]
// BAD - 114
void example_1_bad(void) {
    char data[256] = {0};
    printf("Enter a DLL name to load: ");
    scanf("%255s", data);

    // POTENTIAL FLAW: Load library using a variable path which could be user-controlled
    HMODULE hLibrary = LoadLibraryA(data);
    if (hLibrary != NULL) {
        FreeLibrary(hLibrary);
        printf("Library loaded and freed successfully\n");
    } else {
        printf("Unable to load library\n");
    }
}

// GOOD - 114
void example_1_good(void) {
    // FIX: Use a fixed, safe path that cannot be influenced by the user
    const char *data = "C:\\Windows\\System32\\kernel32.dll";

    HMODULE hLibrary = LoadLibraryA(data);
    if (hLibrary != NULL) {
        FreeLibrary(hLibrary);
        printf("Library loaded and freed successfully\n");
    } else {
        printf("Unable to load library\n");
    }
}


// [LLM PASS]
// BAD - 114
void example_2_bad(void) {
    char command[256];
    printf("Enter a command to execute: ");
    scanf("%255s", command);

    // POTENTIAL FLAW: Execute a command that might be user-controlled
    system(command);
}

// GOOD - 114
void example_2_good(void) {
    // FIX: Execute a fixed, safe command
    const char *command = "dir"; // For Unix-like systems use "ls"

    system(command);
}

int main() {
    example_1_bad();
    example_1_good();
    example_2_bad();
    example_2_good();
    return 0;
}

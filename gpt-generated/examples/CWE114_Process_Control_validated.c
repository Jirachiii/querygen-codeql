#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// BAD - CWE-114: Loading a shared library from a path read from a file
void file_library_load_bad() {
    FILE *file = fopen("library_path.txt", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    char libraryPath[256];
    // POTENTIAL FLAW: Reading library path from an untrusted file
    if (fgets(libraryPath, sizeof(libraryPath), file) == NULL) {
        perror("fgets");
        fclose(file);
        return;
    }
    fclose(file);

    libraryPath[strcspn(libraryPath, "\n")] = '\0'; // Remove newline character

#ifdef _WIN32
    HMODULE hLibrary = LoadLibraryA(libraryPath);
    if (hLibrary != NULL) {
        FreeLibrary(hLibrary);
        printf("Library loaded and freed successfully (bad)\n");
    } else {
        printf("Unable to load library (bad)\n");
    }
#else
    void *hLibrary = dlopen(libraryPath, RTLD_LAZY);
    if (hLibrary) {
        dlclose(hLibrary);
        printf("Library loaded and freed successfully (bad)\n");
    } else {
        printf("Unable to load library (bad)\n");
    }
#endif
}

// GOOD - Ensuring library path is trusted and hard-coded
void file_library_load_good() {
    const char *trustedLibraryPath = "C:\\Windows\\System32\\kernel32.dll"; // Example for Windows

#ifdef _WIN32
    HMODULE hLibrary = LoadLibraryA(trustedLibraryPath);
    if (hLibrary != NULL) {
        FreeLibrary(hLibrary);
        printf("Library loaded and freed successfully (good)\n");
    } else {
        printf("Unable to load library (good)\n");
    }
#else
    void *hLibrary = dlopen("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY); // Example for Linux
    if (hLibrary) {
        dlclose(hLibrary);
        printf("Library loaded and freed successfully (good)\n");
    } else {
        printf("Unable to load library (good)\n");
    }
#endif
}


#include <stdio.h>
#include <windows.h>

// Utility function for error logging
void logError(const char *message) {
    fprintf(stderr, "Error: %s - %ld\n", message, GetLastError());
}


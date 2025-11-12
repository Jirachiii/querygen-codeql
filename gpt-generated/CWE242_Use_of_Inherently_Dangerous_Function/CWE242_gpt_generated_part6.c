#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `strncpy` forgetting to null-terminate, leading to buffer overflow risk
void vulnerable_strncpy_example(const char *src) {
    char buffer[BUFFER_SIZE];
    // Potential issue if buffer is not null-terminated
    strncpy(buffer, src, sizeof(buffer));
    printf("Copied string: %s\n", buffer);
}

// GOOD - Safely using `strncpy` by explicitly null-terminating
void safe_strncpy_example(const char *src) {
    char buffer[BUFFER_SIZE];
    // Copying with safety due to explicit null-termination
    strncpy(buffer, src, sizeof(buffer) - 1);
    buffer[BUFFER_SIZE - 1] = '\0'; // Ensuring null-termination
    printf("Copied string: %s\n", buffer);
}

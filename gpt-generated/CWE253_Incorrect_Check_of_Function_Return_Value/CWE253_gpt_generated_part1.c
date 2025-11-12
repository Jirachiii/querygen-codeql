#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value for memory allocation
void vulnerable_example_1(void) {
    char *buffer;
    buffer = (char *)malloc(10);
    // FLAW: Incorrectly checks if allocation was successful
    if (buffer != 0) {
        strcpy(buffer, "Hello");
        printf("Buffer Content: %s\n", buffer);
    }
    free(buffer);
}

// GOOD - Properly checking the return value of malloc
void safe_example_1(void) {
    char *buffer;
    buffer = (char *)malloc(10);
    // Correctly checks if allocation failed
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        return;
    }
    strcpy(buffer, "Hello");
    printf("Buffer Content: %s\n", buffer);
    free(buffer);
}

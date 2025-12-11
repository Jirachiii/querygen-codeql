#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Constants for buffer sizes
#define SMALL_BUFFER_SIZE 32
#define LARGE_BUFFER_SIZE 1024

// BAD - CWE-242: Use of inherently dangerous function gets in processing user input
void processUserInput_bad() {
    char buffer[SMALL_BUFFER_SIZE];
    printf("Enter some text: ");
    // FLAW: gets is inherently dangerous because it does not check buffer lengths
    if (gets(buffer) == NULL) {
        printf("Error reading input\n");
        exit(1);
    }
    buffer[SMALL_BUFFER_SIZE - 1] = '\0'; // Attempt to null-terminate just in case
    printf("You entered: %s\n", buffer);
}

// GOOD - Safe alternative using fgets for processing user input
void processUserInput_good() {
    char buffer[SMALL_BUFFER_SIZE];
    printf("Enter some text: ");
    // fgets limits the number of characters read to the buffer size
    if (fgets(buffer, SMALL_BUFFER_SIZE, stdin) == NULL) {
        printf("Error reading input\n");
        exit(1);
    }
    // Remove newline character if present
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("You entered: %s\n", buffer);
}


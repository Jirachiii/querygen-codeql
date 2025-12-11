#include <stdio.h>
#include <string.h>

typedef struct {
    int importantData;
    char buffer[50];
} customStruct;

// BAD - CWE-121: Stack-based buffer overflow due to insufficient buffer size for file I/O
void handlingFileBad(void) {
    FILE *file = fopen("input.txt", "r");
    char buffer[128];  // small buffer on stack

    if (file) {
        // WARNING: No check for the actual size of the input, potential overflow if file content > 128 bytes
        fread(buffer, sizeof(char), 256, file); 
        fclose(file);
    }
    printf("Read from file: %s\n", buffer);
}

// GOOD - Secure handling of file input
void handlingFileGood(void) {
    FILE *file = fopen("input.txt", "r");
    char buffer[256];  // correctly sized buffer on stack

    if (file) {
        // Ensures no overflow by reading only up to the size of the buffer minus the null terminator
        size_t bytesRead = fread(buffer, sizeof(char), sizeof(buffer) - 1, file);
        buffer[bytesRead] = '\0';  // null-terminate the buffer safely
        fclose(file);
    }
    printf("Read from file: %s\n", buffer);
}

// BAD - CWE-121: Stack-based buffer overflow with user input
void handleUserInputBad(void) {
    char input[10];  // small buffer on stack

    printf("Enter some text: ");
    // Dangerous: using gets which does not check for buffer boundaries
    gets(input); 

    printf("User input: %s\n", input);
}

// GOOD - Secure handling of user input
void handleUserInputGood(void) {
    char input[10];  // buffer with a size limit

    printf("Enter some text: ");
    // Using fgets safely, limits input to buffer size minus one for the null terminator
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // Properly null-terminated input, safe from overflow
        printf("User input: %s\n", input);
    }
}

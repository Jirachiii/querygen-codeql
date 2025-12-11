#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-127: Buffer Under-read due to negative pointer arithmetic during file reading
void fileReadUnderreadBad(char *filename) {
    FILE *file;
    char *buffer;
    size_t bufferSize = 256;

    buffer = (char *)malloc(bufferSize);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        return;
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(buffer);
        return;
    }

    // Intentional underread error
    // Attempting to read data starting from before the allocated buffer
    char *readBuffer = buffer - 5;
    fread(readBuffer, sizeof(char), bufferSize, file);

    printf("Data: %s\n", readBuffer);

    fclose(file);
    free(buffer);
}

// GOOD - Safely read data from a file
void fileReadUnderreadSafe(char *filename) {
    FILE *file;
    char *buffer;
    size_t bufferSize = 256;

    buffer = (char *)malloc(bufferSize);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        return;
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(buffer);
        return;
    }

    // Properly using allocated buffer
    fread(buffer, sizeof(char), bufferSize - 1, file);
    buffer[bufferSize - 1] = '\0'; // Ensure null termination

    printf("Data: %s\n", buffer);

    fclose(file);
    free(buffer);
}


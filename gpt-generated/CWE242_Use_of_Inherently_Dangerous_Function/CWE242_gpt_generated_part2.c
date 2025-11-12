#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `strcpy` without ensuring source string size, can lead to buffer overflow
void vulnerable_file_to_buffer(char* filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file.\n");
        return;
    }
    // Dangerous if file content is larger than buffer
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        printf("Failed to read from file.\n");
        fclose(file);
        return;
    }
    fclose(file);
    printf("File content: %s\n", buffer);
}

// GOOD - Uses `fgets` to safely read file content within buffer limits
void safe_file_to_buffer(char* filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file.\n");
        return;
    }
    // Safely reads the file content
    if (fgets(buffer, BUFFER_SIZE, file) == NULL) {
        printf("Failed to read from file.\n");
        fclose(file);
        return;
    }
    fclose(file);
    // removes newline character
    buffer[strcspn(buffer, "\n")] = 0;
    printf("File content: %s\n", buffer);
}

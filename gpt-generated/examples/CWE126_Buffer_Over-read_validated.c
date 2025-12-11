#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-126: Buffer Over-read via File I/O
void fileRead_bad() {
    FILE *file = fopen("input.txt", "r");
    char buffer[10];
    
    if (file) {
        // POTENTIAL FLAW: Reading more data than buffer can hold without checking file size
        fread(buffer, sizeof(char), 20, file); // Over-reads if file is larger than 10 bytes
        buffer[9] = '\0'; // Ensure null termination
        printf("Data read: %s\n", buffer);
        fclose(file);
    } else {
        printf("Failed to open file\n");
    }
}

// GOOD - Handles file read safely
void fileRead_good() {
    FILE *file = fopen("input.txt", "r");
    char buffer[10];

    if (file) {
        size_t bytesRead = fread(buffer, sizeof(char), sizeof(buffer) - 1, file);
        buffer[bytesRead] = '\0'; // Null-terminate correctly within bounds
        printf("Data read: %s\n", buffer);
        fclose(file);
    } else {
        printf("Failed to open file\n");
    }
}


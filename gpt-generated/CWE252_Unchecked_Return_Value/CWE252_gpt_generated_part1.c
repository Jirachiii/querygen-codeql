#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Does not check return value of fopen, potential NULL dereference
void vulnerable_file_io(void) {
    FILE *file = fopen("example.txt", "r");
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);
    printf("%s\n", buffer);
    fclose(file);
}

// GOOD - Checks whether fopen succeeds before using the file pointer
void safe_file_io(void) {
    FILE *file = fopen("example.txt", "r");
    if (file != NULL) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), file) != NULL) {
            printf("%s\n", buffer);
        }
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open file\n");
    }
}

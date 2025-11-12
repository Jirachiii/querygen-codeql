#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value from fopen()
void vulnerable_example_2(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    // FLAW: Incorrect check, should use "== NULL"
    if (file != 0) {
        printf("File opened successfully\n");
        fclose(file);
    }
}

// GOOD - Properly checking the return value of fopen()
void safe_example_2(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    printf("File opened successfully\n");
    fclose(file);
}

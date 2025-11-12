#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value from remove()
void vulnerable_example_5(void) {
    int result = remove("nonexistent.txt");
    // FLAW: Incorrect check, should use "== 0"
    if (result == 1) {
        printf("File removed successfully\n");
    } else {
        printf("Failed to remove file\n");
    }
}

// GOOD - Proper check of return value from remove()
void safe_example_5(void) {
    int result = remove("nonexistent.txt");
    if (result == 0) {
        printf("File removed successfully\n");
    } else {
        perror("Error removing file");
    }
}

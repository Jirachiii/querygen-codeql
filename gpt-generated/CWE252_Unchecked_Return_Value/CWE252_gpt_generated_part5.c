#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Does not check the return value of remove, which may indicate failure
void vulnerable_file_operation(void) {
    remove("example.txt");
}

// GOOD - Checks the return value of remove to confirm file deletion
void safe_file_operation(void) {
    if (remove("example.txt") != 0) {
        fprintf(stderr, "Failed to delete file\n");
    }
}

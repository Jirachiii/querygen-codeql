#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// BAD - CWE-134: Uses user input as format string without validation or sanitization
void userInputBad() {
    char input[100];
    printf("Enter your name: ");
    if (fgets(input, sizeof(input), stdin)) {
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }
        // POTENTIAL FLAW: Using user input directly as the format string
        printf(input);
    }
}

// GOOD - Validate user input and use a fixed format string
void userInputGood() {
    char input[100];
    printf("Enter your name: ");
    if (fgets(input, sizeof(input), stdin)) {
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }
        // FIX : Using a fixed format string
        printf("Hello, %s!\n", input);
    }
}

// BAD - CWE-134: Loads format string from a file without validation or sanitization
void fileInputBad() {
    FILE *file = fopen("input.txt", "r");
    if (file) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), file)) {
            // POTENTIAL FLAW: Using file content directly as format string
            printf(buffer);
        }
        fclose(file);
    }
}

// GOOD - Use a fixed format string and pass file content as an argument
void fileInputGood() {
    FILE *file = fopen("input.txt", "r");
    if (file) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), file)) {
            // FIX: Use fixed format string
            printf("File content: %s", buffer);
        }
        fclose(file);
    }
}

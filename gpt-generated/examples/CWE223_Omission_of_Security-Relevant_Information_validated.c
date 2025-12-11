#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-223: Omission of Security-Relevant Information during file I/O
void file_operation_bad() {
    char line[256];
    FILE *file = fopen("config.txt", "r");

    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        // FLAW: Log that an operation occurred without detailed information about the line
        printf("Read a line from file.\n");
    }

    fclose(file);
}

// GOOD - Includes security-relevant information by logging file lines
void file_operation_good() {
    char line[256];
    FILE *file = fopen("config.txt", "r");

    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        // Log detailed information for each line
        printf("Read line: %s", line);
    }

    fclose(file);
}

// BAD - CWE-223: Omission of Security-Relevant Information during user input processing
void user_input_processing_bad() {
    char buffer[128];
    printf("Enter command: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // FLAW: Command execution without logging the user input
        system(buffer);
        printf("Executed command.\n");
    }
}

// GOOD - Logs security-relevant information when processing user input
void user_input_processing_good() {
    char buffer[128];
    printf("Enter command: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Securely log the command being executed
        printf("Executing command: %s", buffer);
        system(buffer);
    }
}

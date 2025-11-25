#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define buffer sizes
#define BUFFER_SIZE 256
#define SAFE_FILE_PATH "safe_input.txt"
#define DANGEROUS_FILE_PATH "dangerous_input.txt"

// BAD - CWE-242: Use of gets for user input
void user_input_bad() {
    char buffer[BUFFER_SIZE];

    // Using gets is inherently dangerous because it doesn't check buffer size
    printf("Enter some input: ");
    gets(buffer);

    printf("You entered: %s\n", buffer);
}

// GOOD - Secure user input using fgets
void user_input_good() {
    char buffer[BUFFER_SIZE];

    // Use fgets to safely read input, providing a buffer size limit
    printf("Enter some input: ");
    if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
        // Remove newline character read by fgets
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("You entered: %s\n", buffer);
    }
    else {
        printf("Error reading input.\n");
    }
}


// BAD - CWE-242: Use of gets for file input
void file_input_bad() {
    char buffer[BUFFER_SIZE];
    FILE *fp = fopen(DANGEROUS_FILE_PATH, "r");

    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    // Using gets from a file stream is inherently dangerous as it doesn't check buffer size
    if (gets(buffer)) {
        printf("File contains: %s\n", buffer);
    } else {
        printf("Error or end of file reached.\n");
    }

    fclose(fp);
}

// GOOD - Secure file input using fgets
void file_input_good() {
    char buffer[BUFFER_SIZE];
    FILE *fp = fopen(SAFE_FILE_PATH, "r");

    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    // Using fgets with a size limit makes this safer for file input
    if (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';  // Remove newline character if present
        printf("File contains: %s\n", buffer);
    } else {
        printf("Error or end of file reached.\n");
    }

    fclose(fp);
}

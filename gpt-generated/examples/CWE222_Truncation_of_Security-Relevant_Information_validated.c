#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// BAD - CWE-222: Truncation of file input, username could be truncated
void fileInput_truncation_bad() {
    FILE *file;
    char buffer[20];
    char truncatedBuf[10];

    // Open file containing usernames
    file = fopen("usernames.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return;
    }

    // Read username from file
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        // Vulnerability: username could be truncated
        strncpy(truncatedBuf, buffer, sizeof(truncatedBuf) - 1);
        truncatedBuf[sizeof(truncatedBuf) - 1] = '\0';  // Null-terminate truncated string

        // Assume we log the username for check-in
        printf("User: %s\n", truncatedBuf);
    }

    fclose(file);
}

// GOOD - CWE-222: Proper handling of file input without truncation
void fileInput_truncation_good() {
    FILE *file;
    char buffer[20];

    // Open file containing usernames
    file = fopen("usernames.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return;
    }

    // Read username from file securely
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';  // Removes newline if present

        // Check length to ensure no truncation has occurred
        if (strlen(buffer) < sizeof(buffer) - 1) {
            // Safely log the full username
            printf("User: %s\n", buffer);
        } else {
            printf("Error: Username too long to process safely.\n");
        }
    }

    fclose(file);
}


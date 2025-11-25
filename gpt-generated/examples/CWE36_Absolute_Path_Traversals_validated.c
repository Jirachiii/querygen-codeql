#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define FILENAME_MAX 260

// BAD - CWE-36: Vulnerable to Absolute Path Traversal using user input for file I/O
void readUserFile_bad(const char *input) {
    char filePath[FILENAME_MAX];

    // POTENTIAL VULNERABILITY: Copying user input directly into file path
    snprintf(filePath, FILENAME_MAX, "%s", input);
    
    FILE *file = fopen(filePath, "r");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }
    
    char buffer[100];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }

    fclose(file);
}

// GOOD - Secure handling by sanitizing the path and restricting to allowed directory
void readUserFile_good(const char *input) {
    const char *baseDir = "/allowed/directory/";
    char filePath[FILENAME_MAX];

    // Secure path construction: Always prefix with a known safe base directory
    snprintf(filePath, FILENAME_MAX, "%s", baseDir);

    // Allow file operations only if the input is a relative path
    if (strstr(input, "..") == NULL) {
        strncat(filePath, input, FILENAME_MAX - strlen(baseDir) - 1);
        FILE *file = fopen(filePath, "r");
        if (file == NULL) {
            perror("Cannot open file");
            return;
        }
        
        char buffer[100];
        while (fgets(buffer, sizeof(buffer), file) != NULL) {
            printf("%s", buffer);
        }
        fclose(file);
    } else {
        printf("Invalid file path.\n");
    }
}

// BAD - CWE-36: Absolute Path Traversal via network data in a server context
void processNetworkData_bad() {
    char receivedPath[FILENAME_MAX] = "/abs/path/file.txt"; // Example path, replace with actual receiving logic

    // Blindly use the received path for file operations
    FILE *file = fopen(receivedPath, "r");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }
    
    char buffer[100];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }

    fclose(file);
}

// GOOD - Restrict file access to a sanctioned directory and validate input data
void processNetworkData_good() {
    char *allowedDir = "/safe/network/directory/";
    char receivedPath[FILENAME_MAX] = "file.txt"; // Simulate safe network data, replace with a sanitized part

    char filePath[FILENAME_MAX];

    // Construct path with restriction to a specific directory
    snprintf(filePath, FILENAME_MAX, "%s%s", allowedDir, receivedPath);

    FILE *file = fopen(filePath, "r");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }
    
    char buffer[100];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }

    fclose(file);
}

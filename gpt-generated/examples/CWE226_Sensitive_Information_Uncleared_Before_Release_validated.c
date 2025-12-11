#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-226: Sensitive data written to a file without clearing buffer
void fileWrite_bad() {
    char buffer[256];
    FILE *file = fopen("sensitive_data.txt", "w");
    if (!file) {
        perror("fopen");
        return;
    }
    
    printf("Enter sensitive data: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        fclose(file);
        return;
    }

    // Strip newline character
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    fprintf(file, "%s", buffer);
    fclose(file);

    // FLAW: The sensitive buffer is not cleared before release
}

// GOOD - Sensitive data cleared from buffer before releasing
void fileWrite_good() {
    char buffer[256];
    FILE *file = fopen("sensitive_data.txt", "w");
    if (!file) {
        perror("fopen");
        return;
    }
    
    printf("Enter sensitive data: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        fclose(file);
        return;
    }

    // Strip newline character
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    fprintf(file, "%s", buffer);
    fclose(file);

    // Clear sensitive information after use
    memset(buffer, 0, sizeof(buffer));
}

// BAD - CWE-226: Sensitive data from network not cleared before hand-off
void networkData_bad() {
    char *buffer = (char *)malloc(1024);
    if (buffer == NULL) {
        perror("malloc");
        return;
    }
    
    // Simulating network data reception
    strcpy(buffer, "SensitiveNetworkData");

    printf("Processed network data\n");
    
    // FLAW: Not clearing sensitive data from the heap before releasing
    free(buffer);
}

// GOOD - Sensitive heap-allocated data is cleared before release
void networkData_good() {
    char *buffer = (char *)malloc(1024);
    if (buffer == NULL) {
        perror("malloc");
        return;
    }
    
    // Simulating network data reception
    strcpy(buffer, "SensitiveNetworkData");

    printf("Processed network data\n");
    
    // Clear sensitive information before release
    memset(buffer, 0, 1024);
    free(buffer);
}

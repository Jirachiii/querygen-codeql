#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-195: Read from a file and incorrectly use signed to unsigned conversion
void file_read_bad() {
    FILE *file;
    int data;
    file = fopen("input.txt", "r");
    if (file == NULL) {
        return;
    }

    // Read a signed integer from file
    if (fscanf(file, "%d", &data) != 1) {
        fclose(file);
        return;
    }
    fclose(file);

    char buffer[100];
    if (data < 100) {
        // Potential flaw: data is interpreted as unsigned
        memset(buffer, 'A', (unsigned int)data);
        buffer[data] = '\0'; // Unsafe if data is negative
        printf("%s\n", buffer);
    }
}

// GOOD - Securely handle the conversion by checking range
void file_read_good() {
    FILE *file;
    int data;
    file = fopen("input.txt", "r");
    if (file == NULL) {
        return;
    }

    // Read a signed integer from file
    if (fscanf(file, "%d", &data) != 1) {
        fclose(file);
        return;
    }
    fclose(file);

    char buffer[100];
    if (data >= 0 && data < 100) {
        // Secure: Ensure data is non-negative before conversion
        memset(buffer, 'A', (unsigned int)data);
        buffer[data] = '\0'; // Safe termination
        printf("%s\n", buffer);
    }
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-124: Buffer Underwrite due to file I/O operations
void file_io_vulnerable(void) {
    FILE *file = fopen("example.txt", "r");
    if (file != NULL) {
        char *buffer = (char *)malloc(100 * sizeof(char));
        if (buffer == NULL) { exit(-1); }

        // FLAW: Incorrectly positioning the buffer pointer by decrementing it
        char *data = buffer - 8;

        // Attempting to read from file into underwritten buffer
        fread(data, 1, 50, file);
        printf("Read data: %s\n", data);

        free(buffer);
        fclose(file);
    }
}

// GOOD - Proper handling of file I/O operations
void file_io_safe(void) {
    FILE *file = fopen("example.txt", "r");
    if (file != NULL) {
        char *buffer = (char *)malloc(100 * sizeof(char));
        if (buffer == NULL) { exit(-1); }

        // Correct usage, no buffer underwrite
        fread(buffer, 1, 50, file);
        buffer[49] = '\0';  // Null-terminate
        printf("Read data: %s\n", buffer);

        free(buffer);
        fclose(file);
    }
}

// BAD - CWE-124: Buffer Underwrite due to network operations
void network_vulnerable(int socket) {
    char *buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) { exit(-1); }

    char *data = buffer - 10;  // FLAW: Underwrite the buffer

    // Simulate receiving data from network into the underwritten buffer
    recv(socket, data, 50, 0);
    printf("Received data: %s\n", data);

    free(buffer);
}

// GOOD - Proper handling of network operations
void network_safe(int socket) {
    char *buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) { exit(-1); }

    // Correct usage, no buffer underwrite
    recv(socket, buffer, 50, 0);
    buffer[49] = '\0'; // Null-terminate
    printf("Received data: %s\n", buffer);

    free(buffer);
}

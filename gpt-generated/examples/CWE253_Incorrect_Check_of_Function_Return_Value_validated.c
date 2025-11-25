#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value from fopen
void fileOpenBad() {
    FILE *file;
    char filename[] = "nonexistent.txt";

    // Incorrectly check if fopen returned NULL
    if (fopen(filename, "r")) {
        printf("File opened successfully (but it might have failed)\n");
    } else {
        printf("Could not open file\n");
    }
    // File not stored, causing potential resource leak
}

// GOOD - Correct check of return value from fopen
void fileOpenGood() {
    FILE *file;
    char filename[] = "nonexistent.txt";

    // Correctly check if fopen returned NULL
    if ((file = fopen(filename, "r")) == NULL) {
        printf("Could not open file\n");
    } else {
        printf("File opened successfully\n");
        fclose(file);  // Ensure proper resource management
    }
}

// BAD - CWE-253: Incorrect check of return value from recv
void networkReceiveBad() {
    int socket = 0;  // Dummy socket for example
    char buffer[1024];

    // Incorrectly check if recv returned -1
    if (recv(socket, buffer, sizeof(buffer), 0) == 0) {
        printf("No data received (but it might have failed)\n");
    } else {
        printf("Data received\n");
    }
    // Potentially using uninitialized data
}

// GOOD - Correct check of return value from recv
void networkReceiveGood() {
    int socket = 0;  // Dummy socket for example
    char buffer[1024];

    // Correctly check if recv returned -1
    ssize_t bytes_received = recv(socket, buffer, sizeof(buffer), 0);
    if (bytes_received == -1) {
        printf("Failed to receive data\n");
    } else if (bytes_received == 0) {
        printf("No data received\n");
    } else {
        printf("Data received\n");
    }
    // buffer can be safely used here as it's determined that recv succeeded
}

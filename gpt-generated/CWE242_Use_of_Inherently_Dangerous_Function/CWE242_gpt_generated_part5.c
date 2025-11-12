#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `read` without size checks leading to potential buffer overflow
void vulnerable_network_read(int socket) {
    char buffer[BUFFER_SIZE];
    // Risk of buffer overflow if incoming data size isn't checked
    if (read(socket, buffer, 256) == -1) {
        printf("Read error.\n");
        exit(1);
    }
    printf("Received data: %s\n", buffer);
}

// GOOD - Uses `recv` with buffer size enforcement for safety
void safe_network_read(int socket) {
    char buffer[BUFFER_SIZE];
    // Limits read to buffer size, ensuring safety
    ssize_t bytes_received = recv(socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        printf("Receive error.\n");
        exit(1);
    }
    buffer[bytes_received] = '\0'; // Ensuring null-termination
    printf("Received data: %s\n", buffer);
}

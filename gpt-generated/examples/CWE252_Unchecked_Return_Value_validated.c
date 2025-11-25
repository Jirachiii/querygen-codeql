#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Unchecked return value of file write operation
void file_write_bad(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        // Handle file open error
        return;
    }
    
    // Attempt to write to file without checking the return value
    fprintf(file, "%s", data);

    fclose(file);
}

// GOOD - Properly checking return value of file write operation
void file_write_good(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        // Handle file open error
        return;
    }
    
    // Check the return value of fprintf to ensure data was written
    if (fprintf(file, "%s", data) < 0) {
        // Handle write error
        perror("Failed to write to file");
    }

    fclose(file);
}

// BAD - CWE-252: Unchecked return value of network receive operation
void network_receive_bad(int socket) {
    char buffer[1024];
    // Attempt to receive data without checking return value for error
    recv(socket, buffer, sizeof(buffer), 0);
    // Continue using buffer assuming data was received properly
    printf("Received data: %s\n", buffer);
}

// GOOD - Properly checking return value of network receive operation
void network_receive_good(int socket) {
    char buffer[1024];
    // Check the return value of recv to ensure data was received correctly
    int bytes_received = recv(socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        // Handle receive error
        perror("Failed to receive data");
    } else {
        buffer[bytes_received] = '\0'; // Null terminate if necessary
        printf("Received data: %s\n", buffer);
    }
}

int main() {
    // For demonstration purposes only
    file_write_bad("output.txt", "Hello, World!");
    file_write_good("output.txt", "Hello, Secure World!");

    int mock_socket = 0;  // Placeholder for a real socket
    network_receive_bad(mock_socket);
    network_receive_good(mock_socket);

    return 0;
}

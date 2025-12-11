#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-284: Insufficient access restriction for network operations
void network_operation_bad(void) {
    char *data = "GET / HTTP/1.1\r\n\r\n";
    int socket_desc = 0; // Assuming socket_desc is a valid socket descriptor
    
    // FLAW: Sending data over network connection without proper access control
    ssize_t bytes_sent = send(socket_desc, data, strlen(data), 0);
    if (bytes_sent < 0) {
        perror("Error sending data");
    } else {
        printf("Data sent over network\n");
    }
}

// GOOD - Ensures access control before network communication
void network_operation_good(void) {
    char *data = "GET / HTTP/1.1\r\n\r\n";
    int socket_desc = 0; // Assuming socket_desc is a valid socket descriptor

    // Assume a function that checks the privilege of current operation
    int user_has_permission = 1; // Set to true for demonstration purposes

    // FIX: Check for access rights before performing network operation
    if (user_has_permission) {
        ssize_t bytes_sent = send(socket_desc, data, strlen(data), 0);
        if (bytes_sent < 0) {
            perror("Error sending data");
        } else {
            printf("Data sent over network\n");
        }
    } else {
        printf("Insufficient permissions for network operation\n");
    }
}

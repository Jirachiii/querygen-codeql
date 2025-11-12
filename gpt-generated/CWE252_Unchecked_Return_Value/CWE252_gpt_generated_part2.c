#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Does not check return value of listen, potential bind issue
void vulnerable_network_socket(void) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(socket_fd, 5);

    int client_socket = accept(socket_fd, NULL, NULL);
    close(client_socket);
    close(socket_fd);
}

// GOOD - Verifies that listen and bind succeeded
void safe_network_socket(void) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == 0) {
        if (listen(socket_fd, 5) == 0) {
            int client_socket = accept(socket_fd, NULL, NULL);
            close(client_socket);
        } else {
            fprintf(stderr, "Failed to listen on socket\n");
        }
    } else {
        fprintf(stderr, "Failed to bind socket\n");
    }
    close(socket_fd);
}

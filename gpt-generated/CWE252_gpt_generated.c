#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Does not check return value of fopen, potential NULL dereference
void vulnerable_file_io(void) {
    FILE *file = fopen("example.txt", "r");
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);
    printf("%s\n", buffer);
    fclose(file);
}

// GOOD - Checks whether fopen succeeds before using the file pointer
void safe_file_io(void) {
    FILE *file = fopen("example.txt", "r");
    if (file != NULL) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), file) != NULL) {
            printf("%s\n", buffer);
        }
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open file\n");
    }
}

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

// BAD - CWE-252: Does not check return value of realloc, potential memory leak
void vulnerable_memory_allocation(void) {
    int *numbers = malloc(10 * sizeof(int));
    numbers = realloc(numbers, 20 * sizeof(int));
    numbers[0] = 42; // Potentially invalid memory access
    free(numbers);
}

// GOOD - Checks return value of realloc to avoid memory leaks and invalid access
void safe_memory_allocation(void) {
    int *numbers = malloc(10 * sizeof(int));
    if (numbers != NULL) {
        int *tmp = realloc(numbers, 20 * sizeof(int));
        if (tmp != NULL) {
            numbers = tmp;
            numbers[0] = 42;
        } else {
            // handle allocation failure, numbers remains valid
            fprintf(stderr, "Failed to reallocate memory\n");
        }
        free(numbers);
    }
}

// BAD - CWE-252: Does not check return value of fgets, risk of using uninitialized data
void vulnerable_user_input(void) {
    char input[50];
    printf("Enter your name: ");
    fgets(input, sizeof(input), stdin);
    printf("Hello, %s\n", input);
}

// GOOD - Checks return value of fgets to ensure valid input data
void safe_user_input(void) {
    char input[50];
    printf("Enter your name: ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        printf("Hello, %s\n", input);
    } else {
        fprintf(stderr, "Input error\n");
    }
}

// BAD - CWE-252: Does not check the return value of remove, which may indicate failure
void vulnerable_file_operation(void) {
    remove("example.txt");
}

// GOOD - Checks the return value of remove to confirm file deletion
void safe_file_operation(void) {
    if (remove("example.txt") != 0) {
        fprintf(stderr, "Failed to delete file\n");
    }
}
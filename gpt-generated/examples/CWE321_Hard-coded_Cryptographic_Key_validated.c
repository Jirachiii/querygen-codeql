#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-321: Using a hard-coded cryptographic key for file encryption
void encrypt_file_bad(const char *filename) {
    const char *hardCodedKey = "12345"; // Hard-coded key
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    printf("Encrypting file with hard-coded key: %s\n", hardCodedKey);
    // Encryption logic using hardCodedKey...
    fclose(file);
}

// GOOD - Securely handling cryptographic key through user input for file encryption
void encrypt_file_good(const char *filename, const char *key) {
    if (!key || strlen(key) < 8) {
        printf("Key is invalid. Must be at least 8 characters.\n");
        return;
    }
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    printf("Encrypting file with user-provided key.\n");
    // Encryption logic using user-provided key...
    fclose(file);
}

// BAD - CWE-321: Using a hard-coded cryptographic key for network communication
void network_send_bad(const char *data) {
    char *serverAddress = "127.0.0.1";
    int port = 8080;
    char *hardCodedKey = "abcde"; // Hard-coded key
    printf("Sending data to %s:%d with hard-coded key: %s\n", serverAddress, port, hardCodedKey);
    // Network sending logic using hardCodedKey...
}

// GOOD - Securely handling cryptographic key for network communication
void network_send_good(const char *data, const char *key) {
    if (!key || strlen(key) < 8) {
        printf("Key is invalid. Must be at least 8 characters.\n");
        return;
    }
    char *serverAddress = "127.0.0.1";
    int port = 8080;
    printf("Sending data to %s:%d with user-provided key.\n", serverAddress, port);
    // Network sending logic using user-provided key...
}

int main() {
    // Demonstration of the usage of functions

    // Vulnerable examples (DO NOT USE IN PRODUCTION)
    encrypt_file_bad("example.txt");
    network_send_bad("Hello, World!");

    // Secure examples
    encrypt_file_good("example.txt", "securekey123");
    network_send_good("Hello, World!", "securekey123");

    return 0;
}

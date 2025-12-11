#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-244: Password read from a file and reallocated without clearing previous memory
void file_password_handling_bad(void) {
    FILE *file = fopen("password.txt", "r");
    if (file == NULL) { exit(-1); }

    char *password = (char *)malloc(100 * sizeof(char));
    if (password == NULL) { exit(-1); }

    if (fgets(password, 100, file) == NULL) {
        // Failure in reading the password
        password[0] = '\0';
    }

    size_t passwordLen = strlen(password);
    if (passwordLen > 0 && password[passwordLen - 1] == '\n') {
        password[passwordLen - 1] = '\0';
    }

    // Reallocate without wiping old memory contents
    password = realloc(password, 200 * sizeof(char));
    if (password == NULL) { exit(-1); }

    // Simulated use of the password
    strcpy(password, "Use of new buffer");

    printf("Password used: %s\n", password);
    free(password);
}

// GOOD - Comment: Password from file properly handled by clearing old memory
void file_password_handling_good(void) {
    FILE *file = fopen("password.txt", "r");
    if (file == NULL) { exit(-1); }

    char *password = (char *)malloc(100 * sizeof(char));
    if (password == NULL) { exit(-1); }

    if (fgets(password, 100, file) == NULL) {
        // Failure in reading the password
        password[0] = '\0';
    }

    size_t passwordLen = strlen(password);
    if (passwordLen > 0 && password[passwordLen - 1] == '\n') {
        password[passwordLen - 1] = '\0';
    }

    // Clear memory before reallocating
    memset(password, 0, 100 * sizeof(char));
    password = realloc(password, 200 * sizeof(char));
    if (password == NULL) { exit(-1); }

    // Simulated use of the password
    strcpy(password, "Use of new buffer");

    printf("Password used: %s\n", password);
    free(password);
}

// BAD - CWE-244: Sensitive data processed via network operations and not cleared before reallocating
void network_data_handling_bad(void) {
    char *sensitiveData = (char *)malloc(150 * sizeof(char));
    if (sensitiveData == NULL) { exit(-1); }

    // Simulate receiving data over a network (using stdin here)
    if (fgets(sensitiveData, 150, stdin) == NULL) {
        sensitiveData[0] = '\0';
    }

    size_t dataLen = strlen(sensitiveData);
    if (dataLen > 0 && sensitiveData[dataLen - 1] == '\n') {
        sensitiveData[dataLen - 1] = '\0';
    }

    // Reallocate without zeroing sensitive data
    sensitiveData = realloc(sensitiveData, 300 * sizeof(char));
    if (sensitiveData == NULL) { exit(-1); }

    // Altered sensitive data usage
    strcpy(sensitiveData, "Network processed data");

    printf("Data processed: %s\n", sensitiveData);
    free(sensitiveData);
}

// GOOD - Comment: Sensitive data in network operation securely reallocated
void network_data_handling_good(void) {
    char *sensitiveData = (char *)malloc(150 * sizeof(char));
    if (sensitiveData == NULL) { exit(-1); }

    // Simulate receiving data over a network (using stdin here)
    if (fgets(sensitiveData, 150, stdin) == NULL) {
        sensitiveData[0] = '\0';
    }

    size_t dataLen = strlen(sensitiveData);
    if (dataLen > 0 && sensitiveData[dataLen - 1] == '\n') {
        sensitiveData[dataLen - 1] = '\0';
    }

    // Clear memory before reallocating
    memset(sensitiveData, 0, 150 * sizeof(char));
    sensitiveData = realloc(sensitiveData, 300 * sizeof(char));
    if (sensitiveData == NULL) { exit(-1); }

    // Altered sensitive data usage
    strcpy(sensitiveData, "Network processed data");

    printf("Data processed: %s\n", sensitiveData);
    free(sensitiveData);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [LLM PASS]
// BAD - 321
void example_1_bad(void) {
    char *cryptoKey = "123456789abcde";  // Hard-coded key
    printf("Using hard coded key: %s\n", cryptoKey);
    // Rest of the cryptographic operations using the hard-coded key...
}

// GOOD - 321
void example_1_good(void) {
    char cryptoKeyBuffer[100];
    printf("Enter the cryptographic key: ");
    if (fgets(cryptoKeyBuffer, sizeof(cryptoKeyBuffer), stdin) != NULL) {
        // Remove newline character from input if present
        size_t len = strlen(cryptoKeyBuffer);
        if (len > 0 && cryptoKeyBuffer[len - 1] == '\n') {
            cryptoKeyBuffer[len - 1] = '\0';
        }
        printf("Using user-provided key: %s\n", cryptoKeyBuffer);
        // Rest of the cryptographic operations using the user-provided key
    }
}


// [LLM PASS]
// BAD - 321
void example_2_bad(void) {
    const char *cryptoKey = "fixed_key_123456";  // Hard-coded key
    printf("Utilizing a fixed key: %s\n", cryptoKey);
    // The cryptographic system continues with this key...
}

// GOOD - 321
void example_2_good(void) {
    char cryptoKeyBuffer[100];
    FILE *keyFile = fopen("keyfile.txt", "r");
    if (keyFile != NULL) {
        if (fgets(cryptoKeyBuffer, sizeof(cryptoKeyBuffer), keyFile) != NULL) {
            // Remove newline character from input if present
            size_t len = strlen(cryptoKeyBuffer);
            if (len > 0 && cryptoKeyBuffer[len - 1] == '\n') {
                cryptoKeyBuffer[len - 1] = '\0';
            }
            printf("Using key from file: %s\n", cryptoKeyBuffer);
            // Continue with cryptographic operations using the key from file...
        }
        fclose(keyFile);
    } else {
        fprintf(stderr, "Failed to open key file.\n");
    }
}

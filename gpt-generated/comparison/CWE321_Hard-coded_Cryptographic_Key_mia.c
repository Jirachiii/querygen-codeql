#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.29
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


// [MIA PASS] Perplexity: 1.62
// BAD - 223
void example_1_bad(void) {
    char buffer[256];
    printf("Enter your password: ");
    fgets(buffer, 256, stdin);

    // Vulnerability: Critical omission of security-relevant action.
    // FLAW: The input data (e.g., a password) is neither logged nor validated.
    if (strcmp(buffer, "super-secret-password\n") == 0) {
        printf("Logged in successfully.\n");
    } else {
        printf("Login failed.\n");
    }
}

// GOOD - 223
void example_1_good(void) {
    char buffer[256];
    printf("Enter your password: ");
    fgets(buffer, 256, stdin);

    // Safe practice: Log relevant security information for monitoring.
    printf("Login attempt with: %s", buffer);

    if (strcmp(buffer, "super-secret-password\n") == 0) {
        printf("Logged in successfully.\n");
    } else {
        printf("Login failed.\n");
    }
}


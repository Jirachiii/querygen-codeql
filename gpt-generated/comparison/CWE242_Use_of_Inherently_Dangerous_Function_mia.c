#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.35
// BAD - 242
void example_1_bad(void) {
    char buffer[128];
    // FLAW: Using gets() which is inherently dangerous since it doesn't check buffer bounds.
    if (gets(buffer) == NULL) {
        printf("Read Error\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

// GOOD - 242
void example_1_good(void) {
    char buffer[128];
    // FIX: Using fgets() which allows us to specify the buffer size.
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Read Error\n");
        exit(1);
    }
    // Removing potentially added newline from fgets
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("You entered: %s\n", buffer);
}


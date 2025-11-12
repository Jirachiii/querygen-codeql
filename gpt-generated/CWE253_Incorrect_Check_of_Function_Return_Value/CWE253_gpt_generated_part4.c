#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value from strcat()
void vulnerable_example_4(void) {
    char dest[10] = "Hello";
    char* result = strcat(dest, "World");
    // FLAW: Incorrect check, strcat returns a pointer to dest, never NULL
    if (result == 0) {
        printf("strcat failed\n");
    } else {
        printf("Concatenated string: %s\n", dest);
    }
}

// GOOD - Proper use of strcat (though no return value check is needed)
void safe_example_4(void) {
    char dest[10] = "Hello";
    // Ensure that strcat does not overflow
    if (strlen(dest) + strlen("World") + 1 <= 10) {
        strcat(dest, "World");
        printf("Concatenated string: %s\n", dest);
    } else {
        printf("Failed to concatenate, buffer too small\n");
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `scanf` without field width, potentially leading to buffer overflow
void vulnerable_scanf_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter a string: ");
    // Vulnerable because no field width is specified
    if (scanf("%s", buffer) != 1) {
        printf("Failed to read input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

// GOOD - Uses field width specifier with `scanf` to prevent overflow
void safe_scanf_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter a string: ");
    // Safe use with specified field width
    if (scanf("%99s", buffer) != 1) {
        printf("Failed to read input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

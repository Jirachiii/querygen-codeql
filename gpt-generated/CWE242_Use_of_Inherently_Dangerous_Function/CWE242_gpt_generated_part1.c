#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `gets` for user input, which does not limit the input size and can cause buffer overflow
void vulnerable_get_user_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter your input: ");
    // Gets is dangerous because it doesn't check the length of input
    if (gets(buffer) == NULL) {
        printf("An error occurred while reading input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

// GOOD - Uses `fgets` to safely get user input
void safe_get_user_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter your input: ");
    // safer than gets as it limits the input size
    if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
        printf("An error occurred while reading input.\n");
        exit(1);
    }
    // removes newline character
    buffer[strcspn(buffer, "\n")] = 0;
    printf("You entered: %s\n", buffer);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

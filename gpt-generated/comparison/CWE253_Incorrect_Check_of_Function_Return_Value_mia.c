#include <stdio.h>
#include <stdlib.h>


// [MIA PASS] Perplexity: 1.34
// BAD - 253
void example_1_bad(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    // FLAW: Incorrectly checks for NULL instead of EOF
    if (fclose(file) == NULL) {
        printf("File close failed!\n");
    }
}

// GOOD - 253
void example_1_good(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    // CORRECT: Check for EOF
    if (file && fclose(file) == EOF) {
        printf("File close failed!\n");
    }
}


// [MIA PASS] Perplexity: 1.25
// BAD - 253
void example_2_bad(void) {
    char buffer[10];
    // FLAW: Incorrectly checks return value as 0 instead of NULL
    if(fgets(buffer, 10, stdin) == 0) {
        printf("Input error!\n");
    }
}

// GOOD - 253
void example_2_good(void) {
    char buffer[10];
    // CORRECT: Check for NULL
    if(fgets(buffer, 10, stdin) == NULL) {
        printf("Input error!\n");
    }
}

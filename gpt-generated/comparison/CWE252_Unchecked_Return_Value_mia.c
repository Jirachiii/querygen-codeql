#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.10
// BAD - 252
void example_1_bad(void) {
    char buffer[50];
    /* FLAW: Do not check the return value of fgets */
    fgets(buffer, sizeof(buffer), stdin);
    printf("Read: %s\n", buffer);
}

// GOOD - 252
void example_1_good(void) {
    char buffer[50];
    /* FIX: Check the return value of fgets */
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        printf("Read: %s\n", buffer);
    } else {
        fprintf(stderr, "Error reading input.\n");
    }
}


// [MIA PASS] Perplexity: 1.06
// BAD - 252
void example_2_bad(void) {
    FILE *file = fopen("example.txt", "r");
    char line[100];
    /* FLAW: Do not check the return value of fgets */
    fgets(line, sizeof(line), file);
    printf("Line: %s\n", line);
    fclose(file);
}

// GOOD - 252
void example_2_good(void) {
    FILE *file = fopen("example.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return;
    }

    char line[100];
    /* FIX: Check the return value of fgets */
    if (fgets(line, sizeof(line), file) != NULL) {
        printf("Line: %s\n", line);
    } else {
        fprintf(stderr, "Error reading line from file.\n");
    }
    
    fclose(file);
}

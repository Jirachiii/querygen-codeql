#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value from scanf()
void vulnerable_example_3(void) {
    int value;
    // FLAW: Incorrect check, should compare result with 1
    if (scanf("%d", &value) == 0) {
        printf("Failed to read integer\n");
    } else {
        printf("Read integer: %d\n", value);
    }
}

// GOOD - Correct check on the return value of scanf()
void safe_example_3(void) {
    int value;
    if (scanf("%d", &value) != 1) {
        printf("Failed to read integer\n");
    } else {
        printf("Read integer: %d\n", value);
    }
}

#include <stdio.h>
#include <stddef.h>

// Function to simulate logging of integer values
void printIntLine(int value) {
    printf("%d\n", value);
}


// [MIA PASS] Perplexity: 1.27
// BAD - 188
void example_2_bad(void) {
    struct {
        char firstChar;
        short shortValue;
        long longValue;
    } dataHolder;

    char *ptr;
    dataHolder.firstChar = 'x';
    dataHolder.shortValue = 100;
    dataHolder.longValue = 5000;

    ptr = &dataHolder.firstChar;
    // FLAW: Assume shortValue is immediately after firstChar
    *(short *)(ptr + 1) = 200; // Incorrect, might disrupt struct padding/alignment

    printf("Expected shortValue: %d\n", 200); // May not be 200
    printf("Actual shortValue: %d\n", dataHolder.shortValue);
}

// GOOD - 188
void example_2_good(void) {
    struct {
        char firstChar;
        short shortValue;
        long longValue;
    } dataHolder;

    dataHolder.firstChar = 'x';
    dataHolder.shortValue = 100;
    dataHolder.longValue = 5000;

    // Access and modify shortValue directly without relying on memory layout assumptions
    dataHolder.shortValue = 200;

    printf("Expected shortValue: %d\n", dataHolder.shortValue);
    printf("Actual shortValue: %d\n", dataHolder.shortValue);
}

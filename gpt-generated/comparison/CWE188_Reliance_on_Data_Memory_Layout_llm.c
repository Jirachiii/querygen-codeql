#include <stdio.h>
#include <stddef.h>

// Function to simulate logging of integer values
void printIntLine(int value) {
    printf("%d\n", value);
}


// [LLM PASS]
// BAD - 188
void example_1_bad(void) {
    struct {
        double doubleValue;
        char charValue;
    } myStruct;

    char *charPtr;
    myStruct.doubleValue = 3.14;
    myStruct.charValue = 'a';
    
    charPtr = (char *)&myStruct.doubleValue;
    // FLAW: Assume charValue is immediately after doubleValue and on a byte-boundary directly after
    *(charPtr + sizeof(double)) = 'b';  // Incorrect, may not modify charValue correctly

    printf("Expected charValue: %c\n", 'b'); // May not be 'b' due to incorrect assumption
    printf("Actual charValue: %c\n", myStruct.charValue);
}

// GOOD - 188
void example_1_good(void) {
    struct {
        double doubleValue;
        char charValue;
    } myStruct;

    myStruct.doubleValue = 3.14;
    myStruct.charValue = 'a';

    // Correctly accessing the charValue directly, without assumptions about memory layout
    myStruct.charValue = 'b';

    printf("Expected charValue: %c\n", myStruct.charValue);
    printf("Actual charValue: %c\n", myStruct.charValue);
}


// [LLM PASS]
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

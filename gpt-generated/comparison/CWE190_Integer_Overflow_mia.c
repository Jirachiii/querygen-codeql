#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

// Function to simulate a random 32-bit unsigned integer
unsigned int RAND32() {
    return (unsigned int)(rand() % UINT_MAX);
}

// Function to print unsigned integer
void printUnsignedLine(unsigned int value) {
    printf("%u\n", value);
}


// [MIA PASS] Perplexity: 1.30
// BAD - Integer Overflow Example 1
void example_1_bad(void) {
    unsigned int data;
    data = 0;

    // POTENTIAL FLAW: Use a random value
    data = RAND32();

    // BAD: No check for overflow here
    unsigned int result = data * 3;
    printUnsignedLine(result);
}

// GOOD - Integer Overflow Mitigation Example 1
void example_1_good(void) {
    unsigned int data;
    data = 0;

    // Use a random value
    data = RAND32();

    // GOOD: Check for potential overflow before multiplication
    if (data <= UINT_MAX / 3) {
        unsigned int result = data * 3;
        printUnsignedLine(result);
    } else {
        printf("Overflow prevented in example_1_good\n");
    }
}


// [MIA PASS] Perplexity: 1.12
// BAD - Integer Overflow Example 2
void example_2_bad(void) {
    unsigned int data;
    data = 0;

    // POTENTIAL FLAW: Use a random value
    data = RAND32();

    // BAD: Addition can lead to overflow
    unsigned int result = data + UINT_MAX;
    printUnsignedLine(result);
}

// GOOD - Integer Overflow Mitigation Example 2
void example_2_good(void) {
    unsigned int data;
    data = 0;

    // Use a random value
    data = RAND32();

    // GOOD: Proper check to prevent overflow
    if (data <= UINT_MAX - 1000) {
        unsigned int result = data + 1000;
        printUnsignedLine(result);
    } else {
        printf("Overflow prevented in example_2_good\n");
    }
}

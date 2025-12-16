#include <stdio.h>
#include <stdlib.h>
#include <limits.h>


// [MIA PASS] Perplexity: 1.27
// BAD - 196
void example_1_bad(void) {
    unsigned int uValue;
    int sValue;
    
    uValue = rand();
    // FLAW: If uValue is larger than INT_MAX, it will be converted to a negative number in sValue
    sValue = uValue;
    printf("Unsigned: %u, Signed: %d\n", uValue, sValue);
}

// GOOD - 196
void example_1_good(void) {
    unsigned int uValue;
    int sValue;
    
    uValue = rand() % (INT_MAX + 1); // Ensure uValue does not exceed INT_MAX
    // Correctly handles the conversion because uValue is within the range of a signed int
    sValue = uValue;
    printf("Unsigned: %u, Signed: %d\n", uValue, sValue);
}


// [MIA PASS] Perplexity: 1.32
// BAD - 196
void example_2_bad(void) {
    unsigned int uValue = 4000000000; // A large unsigned value greater than INT_MAX
    int sValue;

    // FLAW: Directly assigning a large unsigned value to a signed integer
    sValue = uValue;
    printf("Unsigned: %u, Signed: %d\n", uValue, sValue);
}

// GOOD - 196
void example_2_good(void) {
    unsigned int uValue = 30000; // A smaller unsigned value that fits within the signed integer range
    int sValue;

    // Correctly assigns an unsigned value that's guaranteed to be within the signed int range
    sValue = uValue;
    printf("Unsigned: %u, Signed: %d\n", uValue, sValue);
}

#include <stdio.h>
#include <stdlib.h>
#include <time.h>


// [MIA PASS] Perplexity: 1.24
// BAD - 338
void example_1_bad(void) {
    int data;
    /* FLAW: Use of rand() as a PRNG */
    data = rand();
    printf("Random number: %d\n", data);
}

// GOOD - 338
void example_1_good(void) {
    int data;
    /* FIX: Use a more secure PRNG */
    unsigned int seed = (unsigned int)time(NULL);
    srandom(seed); // Using srandom for better randomness
    data = random();
    printf("Random number: %d\n", data);
}


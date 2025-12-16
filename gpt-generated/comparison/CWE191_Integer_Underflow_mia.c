#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>


// [MIA PASS] Perplexity: 1.44
// BAD - CWE-191
// This function demonstrates a potential underflow by decrementing a random char value
void example_1_bad(void) {
    char data;
    data = (char)(rand() % 256);  // POTENTIAL FLAW: Using a random value

    printf("Before decrementing, data: %d \n", data);
    
    // Potential underflow if 'data' is 0, it will wrap around to CHAR_MAX
    data--;
    
    printf("After decrementing, data: %d \n", data);
}

// GOOD - CWE-191
// This function prevents underflow by checking value before decrementing
void example_1_good(void) {
    char data;
    data = (char)(rand() % 256);

    printf("Before safe decrementing, data: %d \n", data);

    // Check to prevent underflow
    if (data > CHAR_MIN) {
        data--;
        printf("After safe decrementing, data: %d \n", data);
    } else {
        printf("Decrementing would cause underflow. Operation skipped.\n");
    }
}


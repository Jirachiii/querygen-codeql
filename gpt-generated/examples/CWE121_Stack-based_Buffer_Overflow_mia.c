#include <stdio.h>
#include <string.h>

// Defining a structure for demonstration purposes
typedef struct {
    int intOne;
    int intTwo;
} twoIntsStruct;


// [MIA PASS] Perplexity: 1.22
// BAD - 121
void example_1_bad(void) {
    twoIntsStruct *data;
    twoIntsStruct dataBadBuffer[10];
    twoIntsStruct dataGoodBuffer[20];

    // Incorrectly set data pointer to a small buffer
    data = dataBadBuffer;
    
    // Source array with a larger size than the destination buffer
    twoIntsStruct source[20];
    for (size_t i = 0; i < 20; i++) {
        source[i].intOne = i;
        source[i].intTwo = i;
    }

    // Potential buffer overflow occurs here
    memmove(data, source, 20 * sizeof(twoIntsStruct));
    printf("example_1_bad: %d\n", data[0].intOne);
}

// GOOD - 121
void example_1_good(void) {
    twoIntsStruct *data;
    twoIntsStruct dataGoodBuffer[20];
    
    // Correctly set data pointer to a sufficiently sized buffer
    data = dataGoodBuffer;
    
    twoIntsStruct source[20];
    for (size_t i = 0; i < 20; i++) {
        source[i].intOne = i;
        source[i].intTwo = i;
    }

    // Safe usage with correctly sized buffer
    memmove(data, source, 20 * sizeof(twoIntsStruct));
    printf("example_1_good: %d\n", data[0].intOne);
}


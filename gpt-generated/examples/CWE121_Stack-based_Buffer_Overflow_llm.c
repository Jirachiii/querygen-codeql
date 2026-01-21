#include <stdio.h>
#include <string.h>

// Defining a structure for demonstration purposes
typedef struct {
    int intOne;
    int intTwo;
} twoIntsStruct;


// [LLM PASS]
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


// [LLM PASS]
// BAD - 121
void example_2_bad(void) {
    char *data;
    char smallBuffer[5];
    char largeBuffer[50];

    // Setting data to point to the insufficiently sized buffer
    data = smallBuffer;

    // Crafting a larger source string
    const char *source = "This string is too long for the small buffer";
    
    // Copying more data than the destination buffer can hold
    strcpy(data, source);
    printf("example_2_bad: %s\n", data);
}

// GOOD - 121
void example_2_good(void) {
    char *data;
    char largeBuffer[50];

    // Using a buffer that is sufficiently large
    data = largeBuffer;

    const char *source = "This string fits well";
    
    // Safe copy operation
    strcpy(data, source);
    printf("example_2_good: %s\n", data);
}

int main() {
    example_1_bad();
    example_1_good();
    example_2_bad();
    example_2_good();
    return 0;
}

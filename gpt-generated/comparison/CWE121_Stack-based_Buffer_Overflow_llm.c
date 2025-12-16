#include <stdio.h>
#include <string.h>


// [LLM PASS]
// BAD - 121
void example_1_bad(void) {
    char buffer[10];
    // FLAW: Using a buffer of insufficient size
    strcpy(buffer, "This string is definitely too long for the buffer");
    printf("Buffer content: %s\n", buffer);
}

// GOOD - 121
void example_1_good(void) {
    char buffer[50];
    // FIX: Ensuring buffer is large enough to hold the string
    strcpy(buffer, "This string fits within the buffer size");
    printf("Buffer content: %s\n", buffer);
}


// [LLM PASS]
// BAD - 121
void example_2_bad(void) {
    int buffer[5];
    int source[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // FLAW: Copying more elements than the destination can hold
    memcpy(buffer, source, 10 * sizeof(int)); 
    printf("Buffer first element: %d\n", buffer[0]);
}

// GOOD - 121
void example_2_good(void) {
    int buffer[10];
    int source[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // FIX: Ensuring destination buffer is large enough
    memcpy(buffer, source, 10 * sizeof(int));
    printf("Buffer first element: %d\n", buffer[0]);
}

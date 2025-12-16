#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>


// [LLM PASS]
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


// [LLM PASS]
// BAD - CWE-191
// This function introduces underflow risk by subtracting a large value
void example_2_bad(void) {
    short data;
    data = -5;  // Setting a small negative value for demonstration

    printf("Initial value of data: %d \n", data);

    // POTENTIAL FLAW: Subtracting a large enough number to cause underflow
    data -= 32768;

    printf("After subtraction, data: %d \n", data);
}

// GOOD - CWE-191
// This function prevents underflow by verifying the operation beforehand
void example_2_good(void) {
    short data;
    data = -5;

    printf("Initial value of data: %d \n", data);

    // Check prevents underflow
    if (data >= (SHORT_MIN + 32768)) {
        data -= 32768;
        printf("After safe subtraction, data: %d \n", data);
    } else {
        printf("Subtraction would cause underflow. Operation skipped.\n");
    }
}

int main() {
    srand((unsigned)time(NULL)); // Initialize random number generator

    printf("Running example_1_bad()...\n");
    example_1_bad();

    printf("\nRunning example_1_good()...\n");
    example_1_good();

    printf("\nRunning example_2_bad()...\n");
    example_2_bad();

    printf("\nRunning example_2_good()...\n");
    example_2_good();

    return 0;
}

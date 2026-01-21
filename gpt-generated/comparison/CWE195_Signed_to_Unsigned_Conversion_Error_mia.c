#include <stdio.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.33
// BAD - 195
void example_1_bad(void) {
    int data;
    char source[100];
    char dest[100] = "";

    // Initialize source array
    memset(source, 'B', 100-1);
    source[100-1] = '\0';

    // FLAW: Use a negative number
    data = -5;

    if (data < 100) {
        // POTENTIAL FLAW: data is interpreted as an unsigned int - if its value is negative,
        // the sign conversion could result in a very large number
        strncpy(dest, source, data);
        dest[data] = '\0'; // strncpy() does not always NULL terminate
    }
    printf("%s\n", dest);
}


// [MIA PASS] Perplexity: 1.30
// GOOD - 195
void example_1_good(void) {
    int data;
    char source[100];
    char dest[100] = "";

    // Initialize source array
    memset(source, 'C', 100-1);
    source[100-1] = '\0';

    // FIX: Use a positive number that is less than the size of dest[]
    data = 10;

    if (data < 100) {
        // Safe use as data is positive and within bounds
        strncpy(dest, source, data);
        dest[data] = '\0'; // strncpy() does not always NULL terminate
    }
    printf("%s\n", dest);
}

// BAD - 195
void example_2_bad(void) {
    int count;
    unsigned int u_count;

    // FLAW: Initialize count with a negative value, then assign to an unsigned int
    count = -10;
    u_count = count;

    if (u_count > 100) {
        // Attempting to loop with a very large number due to sign conversion
        for (unsigned int i = 0; i < u_count; i++) {
            printf("This is a potential infinite loop!\n");
        }
    }
}

// GOOD - 195
void example_2_good(void) {
    int count;
    unsigned int u_count;

    // FIX: Use a positive value to avoid the conversion issue
    count = 5;
    u_count = count;

    if (u_count < 100) {
        // Safe loop as u_count's value is small and non-negative
        for (unsigned int i = 0; i < u_count; i++) {
            printf("Looping safely with a positive count\n");
        }
    }
}

int main(void) {
    example_1_bad();
    example_2_bad();
    example_1_good();
    example_2_good();
    return 0;
}

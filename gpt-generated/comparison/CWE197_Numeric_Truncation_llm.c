#include <stdio.h>
#include <stdlib.h>
#include <time.h>


// [LLM PASS]
// BAD - 197
void example_1_bad(void) {
    // This example generates a random short value and casts it to a char,
    // potentially causing a truncation error.
    short data;
    char charData;

    // Seed randomness
    srand((unsigned)time(NULL));
    data = (short)(rand() % (SHRT_MAX + 1));

    // POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error
    charData = (char)data;
    printf("Truncated short %d to char %d\n", data, charData);
}

// GOOD - 197
void example_1_good(void) {
    // This example ensures the short value is within the char range before casting.
    short data;
    char charData;

    // Safe value that ensures no truncation error
    data = 100;  // within the range of char (-128 to 127)

    // No truncation error will happen here
    charData = (char)data;
    printf("Safely converted short %d to char %d\n", data, charData);
}


// [LLM PASS]
// BAD - 197
void example_2_bad(void) {
    // This example uses a large number for an unsigned short
    // and casts it to a char, causing truncation.
    unsigned short data = 300;  // A value greater than the max char range of 127
    char charData;

    // POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error
    charData = (char)data;
    printf("Truncated unsigned short %u to char %d\n", data, charData);
}

// GOOD - 197
void example_2_good(void) {
    // This example explicitly checks the bounds to avoid a truncation error.
    unsigned short data = 100;  // A safe value that can fit within a char
    char charData;

    // Explicitly validate
    if (data <= 127) {
        charData = (char)data;
        printf("Safely converted unsigned short %u to char %d\n", data, charData);
    } else {
        printf("Value %u is out of char range, truncation avoided.\n", data);
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CHAR_ARRAY_SIZE 50
#define SAFE_CONVERSION_MAX 32767

// BAD - CWE-197: Numeric truncation in user input processing
void vulnerable_user_input(void) {
    int data;
    char inputBuffer[CHAR_ARRAY_SIZE];
    // POTENTIAL FLAW: Missing validation on direct user input conversion
    if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL) {
        data = atoi(inputBuffer);
        short shortData = (short)data;
        printf("Truncated user data: %d\n", shortData);
    }
}

// GOOD - Validate user input before converting to smaller integer type
void safe_user_input(void) {
    int data;
    char inputBuffer[CHAR_ARRAY_SIZE];
    if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL) {
        data = atoi(inputBuffer);
        // SAFE: Verify data falls within acceptable short range
        if (data >= -SAFE_CONVERSION_MAX && data <= SAFE_CONVERSION_MAX) {
            short shortData = (short)data;
            printf("Safely converted user data: %d\n", shortData);
        } else {
            printf("Data outside safe range; conversion skipped.\n");
        }
    }
}

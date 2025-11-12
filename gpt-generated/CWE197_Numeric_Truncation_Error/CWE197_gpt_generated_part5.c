#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CHAR_ARRAY_SIZE 50
#define SAFE_CONVERSION_MAX 32767

// BAD - CWE-197: Numeric truncation in struct field conversion
void vulnerable_struct_conversion(void) {
    struct {
        int largeValue;
    } dataStruct;
    dataStruct.largeValue = 99000;
    // POTENTIAL FLAW: Direct truncation without checks
    short shortData = (short)dataStruct.largeValue;
    printf("Truncated struct value: %d\n", shortData);
}

// GOOD - Ensure struct field value is safe for conversion
void safe_struct_conversion(void) {
    struct {
        int largeValue;
    } dataStruct;
    dataStruct.largeValue = 99000;
    // SAFE: Check struct field value within safe range
    if (dataStruct.largeValue >= -SAFE_CONVERSION_MAX && dataStruct.largeValue <= SAFE_CONVERSION_MAX) {
        short shortData = (short)dataStruct.largeValue;
        printf("Safely converted struct value: %d\n", shortData);
    } else {
        printf("Struct value too large; truncation prevented.\n");
    }
}

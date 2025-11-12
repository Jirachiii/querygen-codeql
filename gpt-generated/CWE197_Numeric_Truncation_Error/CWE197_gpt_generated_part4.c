#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CHAR_ARRAY_SIZE 50
#define SAFE_CONVERSION_MAX 32767

// BAD - CWE-197: Numeric truncation from processing large numbers in arrays
void vulnerable_array_processing(void) {
    int dataArray[] = { 100000, -50000, 40000 };
    for (int i = 0; i < 3; i++) {
        // POTENTIAL FLAW: Truncating large numbers without cheсking
        short shortData = (short)dataArray[i];
        printf("Truncated array element: %d\n", shortData);
    }
}

// GOOD - Verify array elements before truncation
void safe_array_processing(void) {
    int dataArray[] = { 100000, -50000, 40000 };
    for (int i = 0; i < 3; i++) {
        // SAFE: Check each element's value before conversion
        if (dataArray[i] >= -SAFE_CONVERSION_MAX && dataArray[i] <= SAFE_CONVERSION_MAX) {
            short shortData = (short)dataArray[i];
            printf("Safely converted array element: %d\n", shortData);
        } else {
            printf("Array element too large/small; conversion omitted.\n");
        }
    }
}

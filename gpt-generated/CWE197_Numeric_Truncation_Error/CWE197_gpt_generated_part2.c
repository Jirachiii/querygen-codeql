#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CHAR_ARRAY_SIZE 50
#define SAFE_CONVERSION_MAX 32767

// BAD - CWE-197: Numeric truncation from network input without validation
void vulnerable_network_input(void) {
    char buffer[CHAR_ARRAY_SIZE];
    int data;
    // Simulate receiving data from network (e.g., through a socket)
    strcpy(buffer, "40000");
    // POTENTIAL FLAW: Convert unchecked input directly to integer
    data = atoi(buffer);
    short shortData = (short)data;
    printf("Truncated data: %d\n", shortData);
}

// GOOD - Validate data from network before conversion
void safe_network_input(void) {
    char buffer[CHAR_ARRAY_SIZE];
    int data;
    // Simulate receiving data from network (e.g., through a socket)
    strcpy(buffer, "40000");
    data = atoi(buffer);
    // SAFE: Ensure data falls within valid range for short before conversion
    if (data >= -SAFE_CONVERSION_MAX && data <= SAFE_CONVERSION_MAX) {
        short shortData = (short)data;
        printf("Safely converted data: %d\n", shortData);
    } else {
        printf("Data too large; potential truncation avoided.\n");
    }
}

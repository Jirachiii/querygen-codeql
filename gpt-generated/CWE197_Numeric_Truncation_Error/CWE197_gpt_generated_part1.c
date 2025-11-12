#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants
#define CHAR_ARRAY_SIZE 50
#define SAFE_CONVERSION_MAX 32767

// BAD - CWE-197: Numeric truncation due to file input with large integer
void vulnerable_file_input(void) {
    int data;
    FILE *file = fopen("data.txt", "r");
    if (file) {
        fscanf(file, "%d", &data);
        fclose(file);
        // POTENTIAL FLAW: Truncate integer to short, possible data loss
        short shortData = (short)data;
        printf("Truncated data: %d\n", shortData);
    } else {
        printf("File open failed.\n");
    }
}

// GOOD - Prevent numeric truncation by checking range before conversion
void safe_file_input(void) {
    int data;
    FILE *file = fopen("data.txt", "r");
    if (file) {
        fscanf(file, "%d", &data);
        fclose(file);
        // SAFE: Check if within the safe range for short
        if (data >= -SAFE_CONVERSION_MAX && data <= SAFE_CONVERSION_MAX) {
            short shortData = (short)data;
            printf("Safely converted data: %d\n", shortData);
        } else {
            printf("Data too large; potential truncation avoided.\n");
        }
    } else {
        printf("File open failed.\n");
    }
}

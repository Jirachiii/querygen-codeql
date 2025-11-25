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

// Make sure to include additional functionality framing such as headers, main function etc.
// This sample provides focused examples of how to create safe and vulnerable numeric conversions.
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // For strncpy
#include <stdint.h> // For int16_t and int8_t

// BAD - CWE-197: Truncation from file reading
void cwe197_file_truncation_bad(const char* fileName) {
    FILE *filePtr = fopen(fileName, "r");
    if (filePtr != NULL) {
        int16_t data;
        if (fscanf(filePtr, "%hd", &data) == 1) {
            // POTENTIAL FLAW: Converting int16_t to int8_t could truncate data
            int8_t truncatedData = (int8_t)data;
            printf("Truncated data: %d\n", truncatedData);
        }
        fclose(filePtr);
    } else {
        printf("Failed to open file.\n");
    }
}

// GOOD - Safe conversion with file reading
void cwe197_file_truncation_good(const char* fileName) {
    FILE *filePtr = fopen(fileName, "r");
    if (filePtr != NULL) {
        int16_t data;
        if (fscanf(filePtr, "%hd", &data) == 1) {
            // SAFE: Check the range before conversion
            if (data >= INT8_MIN && data <= INT8_MAX) {
                int8_t safeData = (int8_t)data;
                printf("Safe data: %d\n", safeData);
            } else {
                printf("Data out of range for int8_t conversion.\n");
            }
        }
        fclose(filePtr);
    } else {
        printf("Failed to open file.\n");
    }
}

// BAD - CWE-197: Truncation from user input
void cwe197_user_input_truncation_bad(void) {
    char inputBuffer[10];
    printf("Enter a number (0-100000): ");
    if (fgets(inputBuffer, sizeof(inputBuffer), stdin) != NULL) {
        int number = atoi(inputBuffer);
        // POTENTIAL FLAW: Converting int to char could truncate data
        char truncatedChar = (char)number;
        printf("Truncated char value: %d\n", truncatedChar);
    } else {
        printf("Failed to read input.\n");
    }
}

// GOOD - Safe conversion with user input
void cwe197_user_input_truncation_good(void) {
    char inputBuffer[10];
    printf("Enter a number (0-100): ");
    if (fgets(inputBuffer, sizeof(inputBuffer), stdin) != NULL) {
        int number = atoi(inputBuffer);
        // SAFE: Check range before conversion to prevent truncation
        if (number >= 0 && number <= CHAR_MAX) {
            char safeChar = (char)number;
            printf("Safe char value: %d\n", safeChar);
        } else {
            printf("Input exceeds range of a char type.\n");
        }
    } else {
        printf("Failed to read input.\n");
    }
}

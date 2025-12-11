#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

// Utility function
unsigned int getRandInt() {
    return (unsigned int)rand();
}

// BAD - CWE-190: Vulnerable to integer overflow via user input multiplication
void userInputProcess_bad() {
    unsigned int num1, num2, result;
    printf("Enter two positive integers: ");
    
    // POTENTIAL FLAW: Taking user input without any checks
    if (scanf("%u %u", &num1, &num2) != 2) {
        printf("Invalid input.\n");
        return;
    }

    // Vulnerable operation
    result = num1 * num2; // POTENTIAL FLAW: Could overflow if num1 * num2 > UINT_MAX
    printf("Result: %u\n", result);
}

// GOOD - Secure user input process avoiding overflow
void userInputProcess_good() {
    unsigned int num1, num2, result;
    printf("Enter two positive integers: ");
    
    if (scanf("%u %u", &num1, &num2) != 2) {
        printf("Invalid input.\n");
        return;
    }

    // Check for overflow before multiplication
    if (num1 > 0 && num2 > 0 && num1 <= UINT_MAX / num2) {
        result = num1 * num2;
        printf("Result safely calculated: %u\n", result);
    } else {
        printf("Potential overflow detected.\n");
    }
}

// BAD - CWE-190: Integer overflow in file processing
void fileDataProcessing_bad() {
    FILE *file = fopen("data.txt", "r");
    int values[10];
    int product = 1, value, i = 0;

    if (!file) {
        printf("Failed to open file.\n");
        return;
    }

    while (fscanf(file, "%d", &value) != EOF && i < 10) {
        values[i++] = value;
    }
    fclose(file);

    // POTENTIAL FLAW: No overflow check
    for (int j = 0; j < i; j++) {
        product *= values[j]; // Could overflow if the resulting product exceeds INT_MAX
    }
    printf("Product of file values: %d\n", product);
}

// GOOD - Safe file processing with overflow check
void fileDataProcessing_good() {
    FILE *file = fopen("data.txt", "r");
    int values[10];
    int product = 1, value, i = 0;

    if (!file) {
        printf("Failed to open file.\n");
        return;
    }

    while (fscanf(file, "%d", &value) != EOF && i < 10) {
        values[i++] = value;
    }
    fclose(file);

    for (int j = 0; j < i; j++) {
        // Check for overflow before processing
        if (values[j] != 0 && (product > INT_MAX / values[j] || product < INT_MIN / values[j])) {
            printf("Overflow detected, result might exceed limits\n");
            return;
        }
        product *= values[j];
    }
    printf("Product of file values safely calculated: %d\n", product);
}

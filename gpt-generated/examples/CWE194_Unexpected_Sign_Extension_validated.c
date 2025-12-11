#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BUFFER_SIZE 128

// BAD - CWE-194: File I/O with improper handling of sign extension
void fileIOExample_bad() {
    FILE *file;
    short data;
    int tempInt;
    char buffer[BUFFER_SIZE];

    file = fopen("input.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    if (fgets(buffer, BUFFER_SIZE, file) != NULL) {
        // Assume buffer contains a signed integer
        tempInt = atoi(buffer);
        // FLAW: Direct conversion without checking for proper range
        data = tempInt; // May result in unexpected sign extension
        printf("Integer read from file: %d\n", data);
    }

    fclose(file);
}

// GOOD - Proper range check before conversion in File I/O
void fileIOExample_good() {
    FILE *file;
    short data;
    int tempInt;
    char buffer[BUFFER_SIZE];

    file = fopen("input.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    if (fgets(buffer, BUFFER_SIZE, file) != NULL) {
        tempInt = atoi(buffer);
        // Ensure the int can be safely converted to short
        if (tempInt <= SHRT_MAX && tempInt >= SHRT_MIN) {
            data = tempInt;
            printf("Integer safely read from file: %d\n", data);
        } else {
            printf("Value out of range for short: %d\n", tempInt);
        }
    }

    fclose(file);
}

// BAD - CWE-194: Network operation with sign extension vulnerability
void networkExample_bad() {
    // Simulating network input with a char array
    char networkBuffer[] = "-12345"; // Simulate network data
    short data;
    int tempInt;

    // Assume networkBuffer is received from a network operation
    tempInt = atoi(networkBuffer);
    // FLAW: Directly assigning received int to short can cause sign extension issues
    data = tempInt;
    printf("Received and converted data: %d\n", data);
}

// GOOD - Proper conversion handling with network data
void networkExample_good() {
    // Simulating network input with a char array
    char networkBuffer[] = "-12345"; // Simulate network data
    short data;
    int tempInt;

    // Assume networkBuffer is received from a network operation
    tempInt = atoi(networkBuffer);
    // Properly check range before assigning
    if (tempInt <= SHRT_MAX && tempInt >= SHRT_MIN) {
        data = tempInt;
        printf("Safely received and converted data: %d\n", data);
    } else {
        printf("Network data out of range for short: %d\n", tempInt);
    }
}

int main() {
    // Call bad and good functions for testing
    printf("Testing fileIOExample_bad():\n");
    fileIOExample_bad();
    
    printf("\nTesting fileIOExample_good():\n");
    fileIOExample_good();
    
    printf("\nTesting networkExample_bad():\n");
    networkExample_bad();
    
    printf("\nTesting networkExample_good():\n");
    networkExample_good();

    return 0;
}

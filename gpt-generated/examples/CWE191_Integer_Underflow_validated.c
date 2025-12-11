#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

// BAD - CWE-191: File I/O reading might cause an underflow when decrementing
void fileInputUnderflowBad() {
    FILE *file = fopen("data.txt", "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int value;
    // POTENTIAL FLAW: No check for EOF, relying on file content entirely
    fscanf(file, "%d", &value);
    fclose(file);

    // Decrement may lead to underflow
    if (value == INT_MIN) {
        printf("Warning: Potential underflow detected before decrement\n");
    } else {
        value--;
    }

    printf("Result after decrement: %d\n", value);
}

// GOOD - 191: Check to prevent underflow
void fileInputUnderflowGood() {
    FILE *file = fopen("data.txt", "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    int value;
    // Secure read with EOF check
    if (fscanf(file, "%d", &value) == EOF) {
        fclose(file);
        printf("End of file or error in reading\n");
        return;
    }
    fclose(file);

    // Prevent underflow by checking before decrement
    if (value > INT_MIN) {
        value--;
        printf("Result after decrement: %d\n", value);
    } else {
        printf("Underflow avoided\n");
    }
}

// BAD - CWE-191: Network operation reading causing underflow
void networkInputUnderflowBad() {
    // Simulate reading from network
    int recvValue = -1;  // This could come from any network source

    // Directly decrementing without check might lead to underflow
    recvValue--;
    printf("Result after decrement: %d\n", recvValue);
}

// GOOD - 191: Network operation preventing underflow
void networkInputUnderflowGood() {
    // Simulate reading from network
    int recvValue = -1;  // This could come from any network source
    
    // Check for underflow before decrement
    if (recvValue > INT_MIN) {
        recvValue--;
        printf("Result after decrement: %d\n", recvValue);
    } else {
        printf("Underflow avoided\n");
    }
}

int main() {
    // Example calls to each function
    fileInputUnderflowBad();
    fileInputUnderflowGood();
    networkInputUnderflowBad();
    networkInputUnderflowGood();
    return 0;
}

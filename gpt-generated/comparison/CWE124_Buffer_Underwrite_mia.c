#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.05
// BAD - 124
void example_1_bad(void) {
    char *data;
    data = NULL;
    {
        char *dataBuffer = (char *)malloc(50 * sizeof(char));
        if (dataBuffer == NULL) { exit(-1); }
        memset(dataBuffer, 'B', 50 - 1);
        dataBuffer[50 - 1] = '\0';
        // FLAW: Set data pointer to before the allocated memory buffer
        data = dataBuffer - 5;
        printf("Data: %s\n", data);
    }
}

// GOOD - 124
void example_1_good(void) {
    char *data;
    data = NULL;
    {
        char *dataBuffer = (char *)malloc(50 * sizeof(char));
        if (dataBuffer == NULL) { exit(-1); }
        memset(dataBuffer, 'B', 50 - 1);
        dataBuffer[50 - 1] = '\0';
        // FIX: Set data pointer to the allocated memory buffer
        data = dataBuffer;
        printf("Data: %s\n", data);
    }
}


// [MIA PASS] Perplexity: 1.16
// BAD - 124
void example_2_bad(void) {
    int *arr;
    arr = NULL;
    {
        int *buffer = (int *)malloc(20 * sizeof(int));
        if (buffer == NULL) { exit(-1); }
        for (int i = 0; i < 20; i++) {
            buffer[i] = 0;  // Initialize buffer with zeroes
        }
        // FLAW: Set arr pointer to before the allocated memory buffer
        arr = buffer - 2;
        arr[0] = 5;  // Potentially writes before the allocated memory
        printf("Arr[0]: %d\n", arr[0]);
    }
}

// GOOD - 124
void example_2_good(void) {
    int *arr;
    arr = NULL;
    {
        int *buffer = (int *)malloc(20 * sizeof(int));
        if (buffer == NULL) { exit(-1); }
        for (int i = 0; i < 20; i++) {
            buffer[i] = 0;  // Initialize buffer with zeroes
        }
        // FIX: Set arr pointer to the allocated memory buffer
        arr = buffer;
        arr[0] = 5;  // Safe access within allocated memory
        printf("Arr[0]: %d\n", arr[0]);
    }
}

#include <stdio.h>
#include <string.h>

// Definition of a custom struct for usage in buffer operations
typedef struct {
    int intOne;
    int intTwo;
} twoIntsStruct;

// BAD - CWE-121: Buffer overflow due to incorrect handling of network data
void network_operation_bad() {
    char buffer[64];
    // Simulated network data reception
    char networkData[128] = "This string simulates data received over a network which is way too long for our small buffer.";
    
    // POTENTIAL FLAW: Copying data without checking the buffer size; may cause overflow
    strcpy(buffer, networkData);

    printf("Received network data: %s\n", buffer);
}


// GOOD - Secure alternative for handling network data
void network_operation_good() {
    char buffer[64];
    char networkData[128] = "This string simulates data received over a network which is way too long for our small buffer.";
    
    // Copy data with size limitation to avoid buffer overflow
    strncpy(buffer, networkData, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination

    printf("Received network data: %s\n", buffer);
}
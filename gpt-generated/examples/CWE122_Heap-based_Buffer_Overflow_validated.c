#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-122: File I/O buffer overflow vulnerability via unchecked fread size
void fileReadBad() {
    FILE *file = fopen("example.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    
    char *buffer = (char *)malloc(50); // small buffer
    if (buffer == NULL) {
        perror("Failed to allocate buffer");
        fclose(file);
        return;
    }
    
    // POTENTIAL FLAW: No size check - fread could read more than 50 bytes
    fread(buffer, 1, 100, file);
    
    printf("Read: %s\n", buffer);
    
    free(buffer);
    fclose(file);
}

// GOOD - Secure file read with proper buffer management
void fileReadGood() {
    FILE *file = fopen("example.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    
    char *buffer = (char *)malloc(100); // allocate sufficient buffer
    if (buffer == NULL) {
        perror("Failed to allocate buffer");
        fclose(file);
        return;
    }
    
    // Good Practice: Limit fread to buffer size
    size_t bytesRead = fread(buffer, 1, 100, file);
    buffer[bytesRead] = '\0'; // Ensure null termination
    
    printf("Read: %s\n", buffer);
    
    free(buffer);
    fclose(file);
}

// BAD - CWE-122: Network data processing with buffer overflow issue
void networkReceiveBad() {
    char *buffer = (char *)malloc(100); // oversize allocation in practice for simulation
    if (buffer == NULL) {
        perror("Failed to allocate buffer");
        return;
    }

    // Simulate network data reception
    strcpy(buffer, "Simulated network data that is too long for the actual buffer"); // buffer overflow

    // Buffer allocated on the heap is incorrectly sized for the simulated input
    char dest[25]; // intentionally small destination buffer
    
    // POTENTIAL FLAW: buffer overflow if buffer is larger than dest
    strcpy(dest, buffer);
    printf("Received: %s\n", dest);
    
    free(buffer);
}

// GOOD - Secure network data processing
void networkReceiveGood() {
    char *buffer = (char *)malloc(100); // reasonably sized buffer
    if (buffer == NULL) {
        perror("Failed to allocate buffer");
        return;
    }

    // Simulate network data reception
    strncpy(buffer, "Simulated network data that fits", 99);
    buffer[99] = '\0'; // Ensures null termination

    char dest[50]; // sufficiently sized destination buffer
    
    // Good Practice: Use strncpy with size limitation
    strncpy(dest, buffer, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0'; // Ensure null termination
    printf("Received: %s\n", dest);

    free(buffer);
}

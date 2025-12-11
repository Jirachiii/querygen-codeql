#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

// BAD - CWE-196: Unsigned to Signed Conversion in file operations
void file_processing_bad() {
    unsigned int file_size;
    int signed_file_size;
    FILE *file = fopen("example.txt", "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        // FLAW: Assuming file size fits in signed integer
        file_size = (unsigned int)ftell(file);
        fclose(file);

        signed_file_size = file_size; // Unsigned to signed conversion error
        char *buffer = (char*)malloc(signed_file_size);
        printf("Allocated buffer size: %d\n", signed_file_size); // Potentially negative size
        if (buffer) {
            free(buffer);
        }
    }
}

// GOOD - Properly handling file size using unsigned types
void file_processing_good() {
    unsigned int file_size;
    FILE *file = fopen("example.txt", "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        file_size = (unsigned int)ftell(file); // Use the correct type
        fclose(file);

        // Ensuring the file size does not exhaust memory
        if (file_size < UINT_MAX) {
            char *buffer = (char*)malloc(file_size);
            if (buffer) {
                printf("Allocated buffer size: %u\n", file_size);
                free(buffer);
            }
        }
    }
}

// BAD - CWE-196: Unsigned to Signed Conversion with user input
void user_input_bad() {
    unsigned int number;
    int signed_number;
    char input[10];
    printf("Enter a number: ");
    if (fgets(input, sizeof(input), stdin)) {
        number = strtoul(input, NULL, 10);
    
        signed_number = number; // Unsigned to signed conversion error
        printf("You entered: %d\n", signed_number); // Potentially negative value
    }
}

// GOOD - Safely handling unsigned user input
void user_input_good() {
    unsigned int number;
    char input[10];
    printf("Enter a number: ");
    if (fgets(input, sizeof(input), stdin)) {
        number = strtoul(input, NULL, 10);
        
        // No conversion to signed, preserving unsigned type
        printf("You entered an unsigned number: %u\n", number);
    }
}

int main() {
    file_processing_bad();
    file_processing_good();
    user_input_bad();
    user_input_good();
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-252: Does not check return value of realloc, potential memory leak
void vulnerable_memory_allocation(void) {
    int *numbers = malloc(10 * sizeof(int));
    numbers = realloc(numbers, 20 * sizeof(int));
    numbers[0] = 42; // Potentially invalid memory access
    free(numbers);
}

// GOOD - Checks return value of realloc to avoid memory leaks and invalid access
void safe_memory_allocation(void) {
    int *numbers = malloc(10 * sizeof(int));
    if (numbers != NULL) {
        int *tmp = realloc(numbers, 20 * sizeof(int));
        if (tmp != NULL) {
            numbers = tmp;
            numbers[0] = 42;
        } else {
            // handle allocation failure, numbers remains valid
            fprintf(stderr, "Failed to reallocate memory\n");
        }
        free(numbers);
    }
}

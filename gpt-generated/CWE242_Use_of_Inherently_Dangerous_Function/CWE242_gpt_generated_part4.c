#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `streadd` without limit guard
void vulnerable_streadd_example(void) {
    char src[] = "some input";
    char dest[BUFFER_SIZE];
    // streadd does not limit destination buffer size leading to potential overflow
    streadd(dest, src, "x");
    printf("Processed string: %s\n", dest);
}

// GOOD - Uses `stpncpy` to prevent buffer overflow safely
void safe_stpncpy_example(void) {
    char src[] = "some input";
    char dest[BUFFER_SIZE];
    // Safe usage with buffer size limit
    stpncpy(dest, src, BUFFER_SIZE - 1);
    dest[BUFFER_SIZE - 1] = '\0'; // Ensuring null-termination
    printf("Processed string: %s\n", dest);
}

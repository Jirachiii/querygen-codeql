#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BAD - CWE-253: Incorrect check of return value for memory allocation
void vulnerable_example_1(void) {
    char *buffer;
    buffer = (char *)malloc(10);
    // FLAW: Incorrectly checks if allocation was successful
    if (buffer != 0) {
        strcpy(buffer, "Hello");
        printf("Buffer Content: %s\n", buffer);
    }
    free(buffer);
}

// GOOD - Properly checking the return value of malloc
void safe_example_1(void) {
    char *buffer;
    buffer = (char *)malloc(10);
    // Correctly checks if allocation failed
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        return;
    }
    strcpy(buffer, "Hello");
    printf("Buffer Content: %s\n", buffer);
    free(buffer);
}

// BAD - CWE-253: Incorrect check of return value from fopen()
void vulnerable_example_2(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    // FLAW: Incorrect check, should use "== NULL"
    if (file != 0) {
        printf("File opened successfully\n");
        fclose(file);
    }
}

// GOOD - Properly checking the return value of fopen()
void safe_example_2(void) {
    FILE *file = fopen("nonexistent.txt", "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    printf("File opened successfully\n");
    fclose(file);
}

// BAD - CWE-253: Incorrect check of return value from scanf()
void vulnerable_example_3(void) {
    int value;
    // FLAW: Incorrect check, should compare result with 1
    if (scanf("%d", &value) == 0) {
        printf("Failed to read integer\n");
    } else {
        printf("Read integer: %d\n", value);
    }
}

// GOOD - Correct check on the return value of scanf()
void safe_example_3(void) {
    int value;
    if (scanf("%d", &value) != 1) {
        printf("Failed to read integer\n");
    } else {
        printf("Read integer: %d\n", value);
    }
}

// BAD - CWE-253: Incorrect check of return value from strcat()
void vulnerable_example_4(void) {
    char dest[10] = "Hello";
    char* result = strcat(dest, "World");
    // FLAW: Incorrect check, strcat returns a pointer to dest, never NULL
    if (result == 0) {
        printf("strcat failed\n");
    } else {
        printf("Concatenated string: %s\n", dest);
    }
}

// GOOD - Proper use of strcat (though no return value check is needed)
void safe_example_4(void) {
    char dest[10] = "Hello";
    // Ensure that strcat does not overflow
    if (strlen(dest) + strlen("World") + 1 <= 10) {
        strcat(dest, "World");
        printf("Concatenated string: %s\n", dest);
    } else {
        printf("Failed to concatenate, buffer too small\n");
    }
}

// BAD - CWE-253: Incorrect check of return value from remove()
void vulnerable_example_5(void) {
    int result = remove("nonexistent.txt");
    // FLAW: Incorrect check, should use "== 0"
    if (result == 1) {
        printf("File removed successfully\n");
    } else {
        printf("Failed to remove file\n");
    }
}

// GOOD - Proper check of return value from remove()
void safe_example_5(void) {
    int result = remove("nonexistent.txt");
    if (result == 0) {
        printf("File removed successfully\n");
    } else {
        perror("Error removing file");
    }
}
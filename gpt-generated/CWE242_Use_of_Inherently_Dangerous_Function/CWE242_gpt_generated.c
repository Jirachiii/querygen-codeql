#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 100

// BAD - CWE-242: Uses `gets` for user input, which does not limit the input size and can cause buffer overflow
void vulnerable_get_user_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter your input: ");
    // Gets is dangerous because it doesn't check the length of input
    if (gets(buffer) == NULL) {
        printf("An error occurred while reading input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

// GOOD - Uses `fgets` to safely get user input
void safe_get_user_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter your input: ");
    // safer than gets as it limits the input size
    if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
        printf("An error occurred while reading input.\n");
        exit(1);
    }
    // removes newline character
    buffer[strcspn(buffer, "\n")] = 0;
    printf("You entered: %s\n", buffer);
}

// BAD - CWE-242: Uses `strcpy` without ensuring source string size, can lead to buffer overflow
void vulnerable_file_to_buffer(char* filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file.\n");
        return;
    }
    // Dangerous if file content is larger than buffer
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        printf("Failed to read from file.\n");
        fclose(file);
        return;
    }
    fclose(file);
    printf("File content: %s\n", buffer);
}

// GOOD - Uses `fgets` to safely read file content within buffer limits
void safe_file_to_buffer(char* filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file.\n");
        return;
    }
    // Safely reads the file content
    if (fgets(buffer, BUFFER_SIZE, file) == NULL) {
        printf("Failed to read from file.\n");
        fclose(file);
        return;
    }
    fclose(file);
    // removes newline character
    buffer[strcspn(buffer, "\n")] = 0;
    printf("File content: %s\n", buffer);
}

// BAD - CWE-242: Uses `scanf` without field width, potentially leading to buffer overflow
void vulnerable_scanf_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter a string: ");
    // Vulnerable because no field width is specified
    if (scanf("%s", buffer) != 1) {
        printf("Failed to read input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

// GOOD - Uses field width specifier with `scanf` to prevent overflow
void safe_scanf_input(void) {
    char buffer[BUFFER_SIZE];
    printf("Enter a string: ");
    // Safe use with specified field width
    if (scanf("%99s", buffer) != 1) {
        printf("Failed to read input.\n");
        exit(1);
    }
    printf("You entered: %s\n", buffer);
}

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

// BAD - CWE-242: Uses `read` without size checks leading to potential buffer overflow
void vulnerable_network_read(int socket) {
    char buffer[BUFFER_SIZE];
    // Risk of buffer overflow if incoming data size isn't checked
    if (read(socket, buffer, 256) == -1) {
        printf("Read error.\n");
        exit(1);
    }
    printf("Received data: %s\n", buffer);
}

// GOOD - Uses `recv` with buffer size enforcement for safety
void safe_network_read(int socket) {
    char buffer[BUFFER_SIZE];
    // Limits read to buffer size, ensuring safety
    ssize_t bytes_received = recv(socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        printf("Receive error.\n");
        exit(1);
    }
    buffer[bytes_received] = '\0'; // Ensuring null-termination
    printf("Received data: %s\n", buffer);
}

// BAD - CWE-242: Uses `strncpy` forgetting to null-terminate, leading to buffer overflow risk
void vulnerable_strncpy_example(const char *src) {
    char buffer[BUFFER_SIZE];
    // Potential issue if buffer is not null-terminated
    strncpy(buffer, src, sizeof(buffer));
    printf("Copied string: %s\n", buffer);
}

// GOOD - Safely using `strncpy` by explicitly null-terminating
void safe_strncpy_example(const char *src) {
    char buffer[BUFFER_SIZE];
    // Copying with safety due to explicit null-termination
    strncpy(buffer, src, sizeof(buffer) - 1);
    buffer[BUFFER_SIZE - 1] = '\0'; // Ensuring null-termination
    printf("Copied string: %s\n", buffer);
}
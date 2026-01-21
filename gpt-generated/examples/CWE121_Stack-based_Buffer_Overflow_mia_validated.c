// MIA Score: -0.2497
// BAD - 121
void example_1_bad(void) {
    char buffer[10];
    // Vulnerable: using gets can lead to buffer overflow
    gets(buffer); 
    printf("Input was: %s\n", buffer);
}

// GOOD - 121
void example_1_good(void) {
    char buffer[10];
    // Safe: using fgets to prevent buffer overflow
    fgets(buffer, sizeof(buffer), stdin);
    // Remove any trailing newline character from input
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("Input was: %s\n", buffer);
}

// MIA Score: -0.1655
// BAD - 121
void example_2_bad(void) {
    char buffer[5];
    // Vulnerable: sprintf can overflow if input is too large
    sprintf(buffer, "Hello, World!");
    printf("Buffer contains: %s\n", buffer);
}

// GOOD - 121
void example_2_good(void) {
    char buffer[5];
    // Safe: using snprintf to limit the number of characters written
    snprintf(buffer, sizeof(buffer), "Hi!");
    printf("Buffer contains: %s\n", buffer);
}
```


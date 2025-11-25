#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>

#define BUFFER_SIZE 256
#define LDAP_PORT 389

// BAD - CWE-90: Constructs LDAP query directly with user input from a file without validation
void file_input_bad() {
    FILE *file;
    char data[BUFFER_SIZE] = "";
    char fileName[] = "user_input.txt";
    size_t len = 0;

    // Attempt to open the file
    file = fopen(fileName, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read data from file
    if (fgets(data, BUFFER_SIZE, file) != NULL) {
        len = strlen(data);
        if (len > 0 && (data[len-1] == '\n')) {
            data[len-1] = '\0'; // Remove newline character
        }
    }
    fclose(file);

    // Construct LDAP query potentially using unsafe data
    LDAP* ldapConnection = ldap_init("localhost", LDAP_PORT);
    if (ldapConnection != NULL) {
        char filter[BUFFER_SIZE];
        snprintf(filter, BUFFER_SIZE, "(uid=%s)", data); // Dangerous, no validation
        ldap_unbind(ldapConnection); // Clean up LDAP resources
    }
}

// GOOD - Securely constructs LDAP query using validated user input from a file
void file_input_good() {
    FILE *file;
    char data[BUFFER_SIZE] = "";
    char fileName[] = "user_input.txt";
    size_t len = 0;

    // Attempt to open the file
    file = fopen(fileName, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read data from file
    if (fgets(data, BUFFER_SIZE, file) != NULL) {
        len = strlen(data);
        if (len > 0 && (data[len-1] == '\n')) {
            data[len-1] = '\0'; // Remove the newline character
        }
    }
    fclose(file);

    // Securely construct LDAP query with validated data
    LDAP* ldapConnection = ldap_init("localhost", LDAP_PORT);
    if (ldapConnection != NULL) {
        char filter[BUFFER_SIZE];
        // Simple example of validation: remove non-alphanumeric characters
        for (size_t i = 0, j = 0; i < len; i++) {
            if (isalnum(data[i])) {
                filter[j++] = data[i];
            }
        }
        snprintf(filter, BUFFER_SIZE, "(uid=%s)", filter); // Safe due to input validation
        ldap_unbind(ldapConnection); // Clean up LDAP resources
    }
}

// BAD - CWE-90: Direct user input (via stdin) used in LDAP query without sanitization
void stdin_input_bad() {
    char data[BUFFER_SIZE];
    size_t len = 0;

    // Read data from stdin
    printf("Enter username: ");
    if (fgets(data, BUFFER_SIZE, stdin) != NULL) {
        len = strlen(data);
        if (len > 0 && (data[len-1] == '\n')) {
            data[len-1] = '\0'; // Remove newline character
        }
    }

    // Construct potential unsafe LDAP query
    LDAP* ldapConnection = ldap_init("localhost", LDAP_PORT);
    if (ldapConnection != NULL) {
        char filter[BUFFER_SIZE];
        snprintf(filter, BUFFER_SIZE, "(uid=%s)", data); // Unsafe, unchecked input included
        ldap_unbind(ldapConnection); // Clean up LDAP resources
    }
}

// GOOD - Securely constructs LDAP query using properly validated user input from stdin
void stdin_input_good() {
    char data[BUFFER_SIZE];
    size_t len = 0;

    // Read data from stdin
    printf("Enter username: ");
    if (fgets(data, BUFFER_SIZE, stdin) != NULL) {
        len = strlen(data);
        if (len > 0 && (data[len-1] == '\n')) {
            data[len-1] = '\0'; // Remove newline character
        }
    }

    // Securely construct LDAP query with validated data
    LDAP* ldapConnection = ldap_init("localhost", LDAP_PORT);
    if (ldapConnection != NULL) {
        char filter[BUFFER_SIZE];
        // Simple example of validation: allow only alphanumeric characters
        for (size_t i = 0, j = 0; i < len; i++) {
            if (isalnum(data[i])) {
                filter[j++] = data[i];
            }
        }
        snprintf(filter, BUFFER_SIZE, "(uid=%s)", filter); // Safe due to validation
        ldap_unbind(ldapConnection); // Clean up LDAP resources
    }
}

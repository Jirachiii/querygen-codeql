#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// BAD - CWE-15: External control of configuration via file input
void change_system_setting_bad_file_input() {
    FILE *file = fopen("config.txt", "r");
    char buffer[256];

    if (file != NULL) {
        fgets(buffer, sizeof(buffer), file);
        // FLAW: Directly using data from a file to set a critical configuration
        if (setenv("SYSTEM_SETTING", buffer, 1) != 0) {
            printf("Error setting system configuration\n");
        }
        fclose(file);
    } else {
        printf("Failed to open config file\n");
    }
}

// GOOD - Secure reading and application of configuration from a file
void change_system_setting_good_file_input() {
    FILE *file = fopen("config.txt", "r");
    char buffer[256];

    if (file != NULL) {
        fgets(buffer, sizeof(buffer), file);
        // Validate and sanitize the input data
        if (strncmp(buffer, "VALID_SETTING", 13) == 0) {
            // SAFE: Set environment only if input matches expected pattern/values
            if (setenv("SYSTEM_SETTING", buffer, 1) != 0) {
                printf("Error setting system configuration\n");
            }
        } else {
            printf("Invalid configuration setting detected.\n");
        }
        fclose(file);
    } else {
        printf("Failed to open config file\n");
    }
}

// BAD - CWE-15: External control of configuration via user input
void change_system_setting_bad_user_input() {
    char inputBuffer[256];

    printf("Enter a new system setting: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    // FLAW: Using unvalidated input to set a system configuration
    if (setenv("SYSTEM_SETTING", inputBuffer, 1) != 0) {
        printf("Error setting system configuration\n");
    }
}

// GOOD - Secure handling of user input for configuration
void change_system_setting_good_user_input() {
    char inputBuffer[256];

    printf("Enter a new system setting: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    // Validate and sanitize the input
    if (strncmp(inputBuffer, "ALLOWED_SETTING", 15) == 0) {
        // SAFE: Only apply settings that match known and expected values
        if (setenv("SYSTEM_SETTING", inputBuffer, 1) != 0) {
            printf("Error setting system configuration\n");
        }
    } else {
        printf("Invalid configuration setting provided.\n");
    }
}

int main(void) {
    // Uncomment to run respective functions
    // change_system_setting_bad_file_input();
    // change_system_setting_good_file_input();
    // change_system_setting_bad_user_input();
    // change_system_setting_good_user_input();
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <malloc.h>

// BAD - CWE-188: Incorrect memory layout assumption during file reading
void readUserData_bad(const char *filename) {
    struct UserData {
        char username[16];
        int age;
    } data;

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Could not open file");
        return;
    }

    // Assume that age follows directly after username, regardless of padding
    fread(data.username, sizeof(data.username), 1, file);
    fread(&data.age, sizeof(data.age), 1, file);

    // Naive assumption that age is stored directly after username
    printf("Username: %s, Age: %d\n", data.username, *(int*)(data.username + 16));

    fclose(file);
}

// GOOD - Proper file reading without layout assumption
void readUserData_good(const char *filename) {
    struct UserData {
        char username[16];
        int age;
    } data;
    memset(&data, 0, sizeof(data));  // Initialize structure

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Could not open file");
        return;
    }

    // Read entire structure at once, respecting potential padding
    fread(&data, sizeof(data), 1, file);
    printf("Username: %s, Age: %d\n", data.username, data.age);

    fclose(file);
}


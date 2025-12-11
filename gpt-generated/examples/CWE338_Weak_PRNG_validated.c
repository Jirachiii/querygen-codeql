#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// BAD - CWE-338: Use of rand() for generating temporary file names
void generateTempFileName_bad() {
    FILE *file;
    int randomNumber = rand(); // Weak PRNG
    char fileName[20];
    snprintf(fileName, sizeof(fileName), "temp_%d.txt", randomNumber);

    // File I/O example
    file = fopen(fileName, "w");
    if (file != NULL) {
        fprintf(file, "Temporary data\n");
        fclose(file);
    } else {
        perror("Failed to create temporary file");
    }
}

// GOOD - Use of a strong PRNG for generating temporary file names
void generateTempFileName_good() {
    FILE *file;
    unsigned int randomNumber;
    char fileName[20];

    // Strong PRNG using C11 random number generation
    randomNumber = arc4random(); // Assuming availability of arc4random()

    snprintf(fileName, sizeof(fileName), "temp_%u.txt", randomNumber);

    // File I/O example
    file = fopen(fileName, "w");
    if (file != NULL) {
        fprintf(file, "Temporary data\n");
        fclose(file);
    } else {
        perror("Failed to create temporary file");
    }
}

// BAD - CWE-338: Use of rand() for seeding user session IDs
void generateSessionID_bad() {
    char sessionID[50];
    int seed = rand(); // Weak PRNG
    srand(seed); // Improper seeding
    int randomID = rand(); // Predictable value

    // Network operation context
    snprintf(sessionID, sizeof(sessionID), "session_%d", randomID);
    printf("Generated Session ID: %s\n", sessionID);
}

// GOOD - Use of a strong PRNG for seeding session IDs
void generateSessionID_good() {
    char sessionID[50];
    unsigned int randomID;

    // Strong PRNG using /dev/urandom
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        fread(&randomID, sizeof(randomID), 1, fp);
        fclose(fp);

        // Network operation context
        snprintf(sessionID, sizeof(sessionID), "session_%u", randomID);
        printf("Generated Session ID: %s\n", sessionID);
    } else {
        perror("Failed to open /dev/urandom");
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

// BAD - CWE-364: Race condition due to signal handler with file I/O
void file_io_bad() {
    FILE *filePtr;
    char *filename = "sample.txt";
    
    // Set a signal handler
    signal(SIGINT, SIG_DFL);

    // Open a file and handle potential opening failure
    filePtr = fopen(filename, "w");
    if (filePtr == NULL) {
        perror("Error opening file");
        exit(1);
    }

    // Write some data to the file
    fprintf(filePtr, "Writing initial data.\n");

    // Vulnerability: If SIGINT interrupts here, filePtr might become invalid
    fclose(filePtr);
    filePtr = NULL;

    // Set a signal handler that doesn't manage race conditions
    signal(SIGINT, SIG_DFL);

    // Another write operation that could cause undefined behavior
    filePtr = fopen(filename, "w");
    if (filePtr != NULL) {
        fprintf(filePtr, "Writing more data.\n");
        fclose(filePtr);
    }
}

// GOOD - Correct signal handling with file I/O
void file_io_good() {
    // Use sigaction for safer signal handling
    struct sigaction sa;
    sa.sa_handler = SIG_IGN; // Ignoring the signal for critical section
    sa.sa_flags = 0; // No flags

    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    FILE *filePtr;
    char *filename = "sample.txt";

    // Opening file safely
    filePtr = fopen(filename, "w");
    if (filePtr == NULL) {
        perror("Error opening file");
        exit(1);
    }

    // Writing data to file safely
    fprintf(filePtr, "Writing initial data.\n");
    fclose(filePtr);

    // Restore the default signal action
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);
}

// BAD - CWE-364: Race condition in signal handler with user input processing
void user_input_bad() {
    char buffer[256];
    signal(SIGINT, SIG_DFL);

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Realistic user input processing
        size_t input_length = strlen(buffer);
        
        // Vulnerability: Race condition if SIGINT interrupts here
        if (buffer[input_length - 1] == '\n') {
            buffer[input_length - 1] = '\0';
        }

        printf("Processed Input: %s\n", buffer);
    }

    // Set a signal handler without proper synchronization
    signal(SIGINT, SIG_DFL);
}

// GOOD - Proper input processing with safe signal handling
void user_input_good() {
    // Use pthread to block signals during critical input processing
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL); // Block SIGINT signals

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Safe user input processing
        size_t input_length = strlen(buffer);
        if (input_length > 0 && buffer[input_length - 1] == '\n') {
            buffer[input_length - 1] = '\0';
        }

        printf("Processed Input: %s\n", buffer);
    }

    // Unblocking the signal after the critical section
    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
}

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

typedef struct {
    int val;
} structSigAtomic;

// Global variables used across multiple functions
volatile sig_atomic_t signalFlag = 0;
structSigAtomic *globalStruct = NULL;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// BAD - CWE-364: Signal handler race in buffer operations
void vulnerable_buffer_ops(void) {
    char *buffer = (char *)malloc(100);
    signal(SIGHUP, [](int sig) {
        if (buffer != NULL) buffer[0] = '\0';
    });
    // Some operation on buffer
    snprintf(buffer, 100, "Some data");
    if (buffer[0] != '\0') {
        free(buffer);  // Might be interrupted here
        buffer = NULL;
    }
}

// GOOD - Secure buffer operations with signal safety
void safe_buffer_ops(void) {
    pthread_mutex_lock(&lock);
    char *buffer = (char *)malloc(100);
    pthread_mutex_unlock(&lock);
    signal(SIGHUP, [](int sig) {
        pthread_mutex_lock(&lock);
        if (buffer != NULL) buffer[0] = '\0';
        pthread_mutex_unlock(&lock);
    });
    // Some operation on buffer
    pthread_mutex_lock(&lock);
    snprintf(buffer, 100, "Some data");
    if (buffer[0] != '\0') {
        free(buffer);  // Freed within a locked section
        buffer = NULL;
    }
    pthread_mutex_unlock(&lock);
}

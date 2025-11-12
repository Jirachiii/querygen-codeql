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

// BAD - CWE-364: Race condition with data structures
void vulnerable_data_structures(void) {
    globalStruct = (structSigAtomic *)malloc(sizeof(structSigAtomic));
    signal(SIGUSR2, [](int sig) {
        if (globalStruct != NULL) globalStruct->val = 3;
    });
    
    globalStruct->val = 5;
    if (globalStruct != NULL) {
        free(globalStruct);
        globalStruct = NULL;  // Set to NULL might be interrupted
    }
}

// GOOD - Proper handling with mutex for data structures
void safe_data_structures(void) {
    pthread_mutex_lock(&lock);
    globalStruct = (structSigAtomic *)malloc(sizeof(structSigAtomic));
    pthread_mutex_unlock(&lock);
    signal(SIGUSR2, [](int sig) {
        pthread_mutex_lock(&lock);
        if (globalStruct != NULL) globalStruct->val = 3;
        pthread_mutex_unlock(&lock);
    });
    
    pthread_mutex_lock(&lock);
    globalStruct->val = 5;
    if (globalStruct != NULL) {
        free(globalStruct);  // Freed within a locked section
        globalStruct = NULL;
    }
    pthread_mutex_unlock(&lock);
}

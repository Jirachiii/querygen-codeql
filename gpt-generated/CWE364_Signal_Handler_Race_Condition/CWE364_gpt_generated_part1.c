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

// BAD - CWE-364: Mixing non-atomic operations with signal handlers in file I/O
void vulnerable_file_io(void) {
    FILE *f = fopen("data.txt", "w");
    globalStruct = (structSigAtomic*)malloc(sizeof(structSigAtomic));
    if (globalStruct == NULL) exit(-1);
    globalStruct->val = 1;
    signal(SIGUSR1, [](int sig) {
        if (globalStruct != NULL) globalStruct->val = 2;
    });
    if (f != NULL) {
        if (globalStruct != NULL) {
            fprintf(f, "%d\n", globalStruct->val);
            free(globalStruct);  // Free might be interrupted
            globalStruct = NULL;
        }
        fclose(f);
    }
}

// GOOD - Using mutex to ensure atomic operation during file I/O
void safe_file_io(void) {
    FILE *f = fopen("data.txt", "w");
    pthread_mutex_lock(&lock);
    globalStruct = (structSigAtomic*)malloc(sizeof(structSigAtomic));
    if (globalStruct == NULL) exit(-1);
    globalStruct->val = 1;
    signal(SIGUSR1, [](int sig) {
        pthread_mutex_lock(&lock);
        if (globalStruct != NULL) globalStruct->val = 2;
        pthread_mutex_unlock(&lock);
    });
    pthread_mutex_unlock(&lock);
    if (f != NULL) {
        pthread_mutex_lock(&lock);
        if (globalStruct != NULL) {
            fprintf(f, "%d\n", globalStruct->val);
            free(globalStruct);  // Freed within a locked section
            globalStruct = NULL;
        }
        pthread_mutex_unlock(&lock);
        fclose(f);
    }
}

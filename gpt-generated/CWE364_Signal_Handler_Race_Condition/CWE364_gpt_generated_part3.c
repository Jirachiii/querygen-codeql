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

// BAD - CWE-364: Unsafe handling in user input processing
void vulnerable_user_input(void) {
    globalStruct = (structSigAtomic *)malloc(sizeof(structSigAtomic));
    scanf("%d", &globalStruct->val);
    signal(SIGALRM, [](int sig) {
        if (globalStruct != NULL) globalStruct->val = 42;
    });
    if (globalStruct != NULL && globalStruct->val != 42) {
        free(globalStruct);
        globalStruct = NULL;
    }
}

// GOOD - Secure handling of user inputs
void safe_user_input(void) {
    pthread_mutex_lock(&lock);
    globalStruct = (structSigAtomic *)malloc(sizeof(structSigAtomic));
    pthread_mutex_unlock(&lock);
    scanf("%d", &globalStruct->val);
    signal(SIGALRM, [](int sig) {
        pthread_mutex_lock(&lock);
        if (globalStruct != NULL) globalStruct->val = 42;
        pthread_mutex_unlock(&lock);
    });
    pthread_mutex_lock(&lock);
    if (globalStruct != NULL && globalStruct->val != 42) {
        free(globalStruct);  // Freed within a locked section
        globalStruct = NULL;
    }
    pthread_mutex_unlock(&lock);
}

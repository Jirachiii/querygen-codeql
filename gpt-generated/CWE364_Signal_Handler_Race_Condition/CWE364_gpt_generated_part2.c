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

// BAD - CWE-364: Access shared variable without protection in network ops
void vulnerable_network_op(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    globalStruct = (structSigAtomic*)malloc(sizeof(structSigAtomic));
    if (globalStruct == NULL) exit(-1);
    globalStruct->val = sock;
    signal(SIGTERM, [](int sig) {
        if (globalStruct != NULL) globalStruct->val = -1;
    });
    // Pretend to do some network operations here
    if (globalStruct->val != -1) {  // Might be changed in the middle
        close(globalStruct->val);
        free(globalStruct);
        globalStruct = NULL;
    }
}

// GOOD - Uses signal-safe variables and checks in network ops
void safe_network_op(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    pthread_mutex_lock(&lock);
    globalStruct = (structSigAtomic*)malloc(sizeof(structSigAtomic));
    if (globalStruct == NULL) exit(-1);
    globalStruct->val = sock;
    signal(SIGTERM, [](int sig) {
        pthread_mutex_lock(&lock);
        if (globalStruct != NULL) globalStruct->val = -1;
        pthread_mutex_unlock(&lock);
    });
    pthread_mutex_unlock(&lock);
    // Pretend to do some network operations here
    pthread_mutex_lock(&lock);
    if (globalStruct->val != -1) {
        close(globalStruct->val);
        free(globalStruct);  // Freed within a locked section
        globalStruct = NULL;
    }
    pthread_mutex_unlock(&lock);
}

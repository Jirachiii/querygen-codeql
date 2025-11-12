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

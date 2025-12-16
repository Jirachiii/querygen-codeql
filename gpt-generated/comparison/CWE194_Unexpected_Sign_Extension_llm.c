#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define CHAR_ARRAY_SIZE 8
#define TCP_PORT 27015
#define LISTEN_BACKLOG 5

void performUnsafeOperation(size_t size) {
    // This function simulates an unsafe operation that could be vulnerable
    // due to unexpected sign extension.
}

void performSafeOperation(size_t size) {
    // This function simulates a safe operation.
}



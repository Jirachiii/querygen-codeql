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



// [MIA PASS] Perplexity: 1.14
// BAD - 194
void example_1_bad(void) {
    short data;
    int tempInt;
    int recvResult;
    char inputBuffer[CHAR_ARRAY_SIZE];
    struct sockaddr_in service;
    int listenSocket = -1;
    int acceptSocket = -1;

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == -1) {
        return;
    }
    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(TCP_PORT);

    if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == -1) {
        close(listenSocket);
        return;
    }
    if (listen(listenSocket, LISTEN_BACKLOG) == -1) {
        close(listenSocket);
        return;
    }

    acceptSocket = accept(listenSocket, NULL, NULL);
    if (acceptSocket == -1) {
        close(listenSocket);
        return;
    }

    recvResult = recv(acceptSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
    if (recvResult == -1 || recvResult == 0) {
        close(listenSocket);
        close(acceptSocket);
        return;
    }
    inputBuffer[recvResult] = '\0';

    tempInt = atoi(inputBuffer);
    if (tempInt > SHRT_MAX || tempInt < SHRT_MIN) {
        data = -1;
    } else {
        data = tempInt;
    }

    size_t size = (size_t)data;
    performUnsafeOperation(size);

    close(listenSocket);
    close(acceptSocket);
}

// BAD - 194
void example_2_bad(void) {
    short data = -1;
    data = -300;  // Explicitly setting a negative number

    size_t size = (size_t)data;  // Incorrect handling of sign extension

    performUnsafeOperation(size);
}


// [MIA PASS] Perplexity: 1.10
// GOOD - 194
void example_1_good(void) {
    short data;
    int tempInt;
    int recvResult;
    char inputBuffer[CHAR_ARRAY_SIZE];
    struct sockaddr_in service;
    int listenSocket = -1;
    int acceptSocket = -1;

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == -1) {
        return;
    }
    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(TCP_PORT);

    if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == -1) {
        close(listenSocket);
        return;
    }
    if (listen(listenSocket, LISTEN_BACKLOG) == -1) {
        close(listenSocket);
        return;
    }

    acceptSocket = accept(listenSocket, NULL, NULL);
    if (acceptSocket == -1) {
        close(listenSocket);
        return;
    }

    recvResult = recv(acceptSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
    if (recvResult == -1 || recvResult == 0) {
        close(listenSocket);
        close(acceptSocket);
        return;
    }
    inputBuffer[recvResult] = '\0';

    tempInt = atoi(inputBuffer);
    if (tempInt > 0 && tempInt <= SHRT_MAX) {  // Ensure only positive numbers are set
        data = tempInt;
    } else {
        data = 0;
    }

    size_t size = (size_t)data;
    performSafeOperation(size);

    close(listenSocket);
    close(acceptSocket);
}

// GOOD - 194
void example_2_good(void) {
    short data = 256;  // Ensure the data is positive
    if (data < 0) {
        data = 0;
    }

    size_t size = (size_t)data;  // Safe handling of size

    performSafeOperation(size);
}

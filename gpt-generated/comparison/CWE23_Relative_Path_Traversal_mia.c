#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSE_SOCKET close
#endif

#define TCP_PORT 27015
#define FILENAME_MAX_LEN 260
#define BASEPATH "/safe/directory/"
#define LISTEN_BACKLOG 5


// [MIA PASS] Perplexity: 1.15
// BAD - 23
// This pair has completely different sources of input and the good example's validation is not throughout enough to mitigate the vulnerability.
void example_1_bad(void) {
    char *data;
    char dataBuffer[FILENAME_MAX_LEN] = BASEPATH;
    data = dataBuffer;

#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;
    size_t dataLen = strlen(data);

    do {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
            break;
        }
        wsaDataInit = 1;
#endif
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            break;
        }
        struct sockaddr_in service;
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = htonl(INADDR_ANY);
        service.sin_port = htons(TCP_PORT);
        
        if (bind(listenSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR) {
            break;
        }
        if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
            break;
        }
        acceptSocket = accept(listenSocket, NULL, NULL);
        if (acceptSocket == SOCKET_ERROR) {
            break;
        }
        int recvResult = recv(acceptSocket, data + dataLen, FILENAME_MAX_LEN - dataLen - 1, 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0) {
            break;
        }
        data[dataLen + recvResult] = '\0';
    } while(0);
    
    if (listenSocket != INVALID_SOCKET) {
        CLOSE_SOCKET(listenSocket);
    }
    if (acceptSocket != INVALID_SOCKET) {
        CLOSE_SOCKET(acceptSocket);
    }
#ifdef _WIN32
    if (wsaDataInit) {
        WSACleanup();
    }
#endif

    FILE *file = fopen(data, "wb+");
    if (file != NULL) {
        fprintf(file, "Test content");
        fclose(file);
    }
}


// [MIA PASS] Perplexity: 1.12
// GOOD - 23
void example_1_good(void) {
    char *data;
    char dataBuffer[FILENAME_MAX_LEN] = BASEPATH;
    data = dataBuffer;
    
    printf("Enter file name: ");
    if (fgets(data + strlen(BASEPATH), FILENAME_MAX_LEN - strlen(BASEPATH), stdin)) {
        data[strcspn(data, "\n")] = 0;  // Remove newline character
    }

    // Validate the file path
    // No ".." allowed
    // Not enough for full mitigation of cwe23
    if (strstr(data, "..") == NULL) {
        FILE *file = fopen(data, "wb+");
        if (file != NULL) {
            fprintf(file, "Test content");
            fclose(file);
        }
    } else {
        printf("Invalid file path!\n");
    }
}

// BAD - 23
void example_2_bad(void) {
    char dataBuffer[FILENAME_MAX_LEN];
    char *data = dataBuffer;
    strcpy(data, BASEPATH);

    printf("Enter file name: ");
    if (fgets(data + strlen(BASEPATH), FILENAME_MAX_LEN - strlen(BASEPATH), stdin)) {
        data[strcspn(data, "\n")] = 0;  // Remove newline character
    }

    FILE *file = fopen(data, "wb+");  // POTENTIAL FLAW: No check on filepath
    if (file != NULL) {
        fprintf(file, "Test content");
        fclose(file);
    }
}

// GOOD - 23
void example_2_good(void) {
    char dataBuffer[FILENAME_MAX_LEN];
    char *data = dataBuffer;
    strncpy(data, BASEPATH, strlen(BASEPATH));

    printf("Enter file name: ");
    if (fgets(data + strlen(BASEPATH), FILENAME_MAX_LEN - strlen(BASEPATH), stdin)) {
        data[strcspn(data, "\n")] = 0;  // Remove newline character
    }

    // Check for dangerous characters
    // No ".." and must start with BASEPATH
    // Not enough for full mitigation of cwe23
    if (strstr(data, "..") == NULL && strncmp(data, BASEPATH, strlen(BASEPATH)) == 0) {
        FILE *file = fopen(data, "wb+");
        if (file != NULL) {
            fprintf(file, "Test content");
            fclose(file);
        }
    } else {
        printf("Invalid file path!\n");
    }
}

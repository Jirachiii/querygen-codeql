#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "Ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#endif

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5
#define FILENAME_MAX 260

void processFilePath(const char *path) {
    printf("Processing file path: %s\n", path);
}


// [MIA PASS] Perplexity: 1.23
// BAD - 36
void example_1_bad(void) {
    char data[FILENAME_MAX] = "";
    char buffer[FILENAME_MAX];
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == NO_ERROR) {
#endif
        struct sockaddr_in service;
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) return;

        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);

        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) != SOCKET_ERROR &&
            listen(listenSocket, LISTEN_BACKLOG) != SOCKET_ERROR) {

            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket != INVALID_SOCKET) {
                recv(acceptSocket, buffer, sizeof(buffer) - 1, 0);
                buffer[sizeof(buffer) - 1] = '\0'; // Ensure NULL termination
                strcpy(data, buffer); // POTENTIAL FLAW: Using external input directly
                processFilePath(data);
            }
        }
        CLOSE_SOCKET(listenSocket);
        CLOSE_SOCKET(acceptSocket);

#ifdef _WIN32
        WSACleanup();
    }
#endif
}

// BAD - 36
void example_2_bad(void) {
    char data[FILENAME_MAX] = "/etc/passwd";
    char inputData[FILENAME_MAX];
    
    printf("Enter path: ");
    if (fgets(inputData, FILENAME_MAX, stdin) != NULL) {
        inputData[strcspn(inputData, "\n")] = '\0'; // Remove newline
        if (inputData[0] != '\0') {
            // POTENTIAL FLAW: Directly concatenating input
            strcat(data, inputData);
            processFilePath(data);
        }
    }
}


// [MIA PASS] Perplexity: 1.17
// GOOD - 36
void example_1_good(void) {
    char data[FILENAME_MAX] = "/user/home/files/";
    char buffer[FILENAME_MAX];
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == NO_ERROR) {
#endif
        struct sockaddr_in service;
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) return;

        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);

        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) != SOCKET_ERROR &&
            listen(listenSocket, LISTEN_BACKLOG) != SOCKET_ERROR) {

            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket != INVALID_SOCKET) {
                recv(acceptSocket, buffer, sizeof(buffer) - 1, 0);
                buffer[sizeof(buffer) - 1] = '\0'; // Ensure NULL termination

                // GOOD PRACTICE: Validate and sanitize input
                if (strstr(buffer, "..") == NULL) {
                    strncat(data, buffer, FILENAME_MAX - strlen(data) - 1);
                    processFilePath(data);
                } else {
                    printf("Invalid path!\n");
                }
            }
        }
        CLOSE_SOCKET(listenSocket);
        CLOSE_SOCKET(acceptSocket);

#ifdef _WIN32
        WSACleanup();
    }
#endif
}

// GOOD - 36
void example_2_good(void) {
    char *basePath = "/user/home/files/";
    char data[FILENAME_MAX];
    strcpy(data, basePath);

    char inputData[FILENAME_MAX];
    printf("Enter a filename: ");
    if (fgets(inputData, FILENAME_MAX, stdin) != NULL) {
        inputData[strcspn(inputData, "\n")] = '\0'; // Remove newline

        // GOOD PRACTICE: Check whether input includes forbidden patterns or is too long
        if (strstr(inputData, "..") == NULL && strlen(inputData) < FILENAME_MAX - strlen(basePath)) {
            strcat(data, inputData);
            processFilePath(data);
        } else {
            printf("Invalid filename!\n");
        }
    }
}

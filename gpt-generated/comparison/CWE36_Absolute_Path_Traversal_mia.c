#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <unistd.h>
#include <arpa/inet.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5
#define BASEPATH "/home/safe_dir/"


// [MIA PASS] Perplexity: 1.12
// BAD - 36
void example_1_bad(void) {
    char buffer[FILENAME_MAX] = "";
    char *data = buffer;
    struct sockaddr_in service;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket != INVALID_SOCKET) {
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);
        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) != SOCKET_ERROR &&
            listen(listenSocket, LISTEN_BACKLOG) != SOCKET_ERROR) {
            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket != SOCKET_ERROR) {
                recv(acceptSocket, data, FILENAME_MAX - 1, 0);
                data[FILENAME_MAX - 1] = '\0'; // Ensure null-termination
                printf("Received path: %s\n", data);
            }
        }
    }

    if (listenSocket != INVALID_SOCKET) CLOSE_SOCKET(listenSocket);
    if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket);
#ifdef _WIN32
    WSACleanup();
#endif
}



// [MIA PASS] Perplexity: 1.12
// GOOD - 36
void example_1_good(void) {
    char buffer[FILENAME_MAX] = BASEPATH;
    char *data = buffer + strlen(BASEPATH);
    struct sockaddr_in service;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket != INVALID_SOCKET) {
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);
        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) != SOCKET_ERROR &&
            listen(listenSocket, LISTEN_BACKLOG) != SOCKET_ERROR) {
            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket != SOCKET_ERROR) {
                recv(acceptSocket, data, FILENAME_MAX - strlen(BASEPATH) - 1, 0);
                data[FILENAME_MAX - strlen(BASEPATH) - 1] = '\0'; // Ensure null-termination
                if (strstr(data, "..") == NULL) { // Simple check to prevent directory traversal
                    printf("Safe received path: %s\n", buffer);
                } else {
                    printf("Potential directory traversal detected!\n");
                }
            }
        }
    }

    if (listenSocket != INVALID_SOCKET) CLOSE_SOCKET(listenSocket);
    if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket);
#ifdef _WIN32
    WSACleanup();
#endif
}

// BAD - 36
void example_2_bad(void) {
    char *data = getenv("USER_PATH");
    if (data) {
        FILE *file = fopen(data, "r");
        if (file) {
            printf("Opened file: %s\n", data);
            fclose(file);
        }
    }
}
// GOOD - 36
void example_2_good(void) {
    const char *safeDir = BASEPATH;
    char safePath[FILENAME_MAX];
    char *userInput = getenv("USER_PATH");

    if (userInput) {
        snprintf(safePath, FILENAME_MAX, "%s%s", safeDir, userInput);
        if (strstr(safePath, "..") == NULL) { // Check to ensure path does not contain directory traversal
            FILE *file = fopen(safePath, "r");
            if (file) {
                printf("Safely opened file: %s\n", safePath);
                fclose(file);
            }
        } else {
            printf("Invalid file path detected!\n");
        }
    }
}

int main() {
    // Example execution
    example_1_bad();
    example_2_bad();
    example_1_good();
    example_2_good();
    return 0;
}

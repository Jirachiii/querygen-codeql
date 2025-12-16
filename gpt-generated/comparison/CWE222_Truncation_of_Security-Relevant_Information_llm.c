#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib") // Linking with ws2_32.lib
#define USERNAME_SIZE 100
#define TRUNCATED_USERNAME_SIZE 50
#define LISTEN_PORT 12345
#define LISTEN_BACKLOG 5
#define DOMAIN "example.com"
#define PASSWORD "password" // Note: In a real-world scenario, never use hardcoded passwords


// [LLM PASS]
// BAD - 222
void example_1_bad(void) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;
    struct sockaddr_in service;
    HANDLE pHandle;
    char username[USERNAME_SIZE + 1];
    char truncatedUsername[TRUNCATED_USERNAME_SIZE + 1];

    // Setup Windows Sockets
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
    
    // Create a listening socket
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // Setup the listening service
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(LISTEN_PORT);

    if (bind(listenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    // Accept connections
    acceptSocket = accept(listenSocket, NULL, NULL);
    if (acceptSocket == INVALID_SOCKET) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    // Receive username
    recv(acceptSocket, username, USERNAME_SIZE, 0);
    username[USERNAME_SIZE] = '\0';

    // Flaw: truncating username without checking its length
    memcpy(truncatedUsername, username, TRUNCATED_USERNAME_SIZE);
    truncatedUsername[TRUNCATED_USERNAME_SIZE] = '\0';

    if (LogonUserA(truncatedUsername, DOMAIN, PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle)) {
        printf("Logged in: %s\n", truncatedUsername);
        CloseHandle(pHandle);
    } else {
        printf("Login failed for: %s\n", truncatedUsername);
    }

    closesocket(acceptSocket);
    closesocket(listenSocket);
    WSACleanup();
}

// GOOD - 222
void example_1_good(void) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;
    struct sockaddr_in service;
    HANDLE pHandle;
    char username[USERNAME_SIZE + 1];

    // Setup Windows Sockets
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
    
    // Create a listening socket
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // Setup the listening service
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(LISTEN_PORT);

    if (bind(listenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    // Accept connections
    acceptSocket = accept(listenSocket, NULL, NULL);
    if (acceptSocket == INVALID_SOCKET) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    // Receive username
    int recvLen = recv(acceptSocket, username, USERNAME_SIZE, 0);
    if (recvLen < 0) {
        closesocket(acceptSocket);
        closesocket(listenSocket);
        WSACleanup();
        return;
    }
    username[recvLen] = '\0';  // Safely null-terminate the received string

    // Safely authenticate using the full username
    if (LogonUserA(username, DOMAIN, PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle)) {
        printf("Logged in: %s\n", username);
        CloseHandle(pHandle);
    } else {
        printf("Login failed for: %s\n", username);
    }

    closesocket(acceptSocket);
    closesocket(listenSocket);
    WSACleanup();
}


// [LLM PASS]
// BAD - 222
void example_2_bad(void) {
    char input[100];
    char truncatedInput[10];
    HANDLE pHandle;

    printf("Enter a command: ");
    fgets(input, sizeof(input), stdin);

    // FLAW: Truncate the command without validating its length or content
    strncpy(truncatedInput, input, sizeof(truncatedInput) - 1);
    truncatedInput[sizeof(truncatedInput) - 1] = '\0';

    if (LogonUserA(truncatedInput, DOMAIN, PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle)) {
        printf("Command processed as: %s\n", truncatedInput);
        CloseHandle(pHandle);
    } else {
        printf("Command not recognized: %s\n", truncatedInput);
    }
}

// GOOD - 222
void example_2_good(void) {
    char input[100];
    HANDLE pHandle;
    char *newlinePos;

    printf("Enter a command: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return; // Failed to read input
    }

    // Remove newline character if it exists
    newlinePos = strchr(input, '\n');
    if (newlinePos != NULL) {
        *newlinePos = '\0';
    }

    // Authenticate using the full input safely
    if (LogonUserA(input, DOMAIN, PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle)) {
        printf("Command processed as: %s\n", input);
        CloseHandle(pHandle);
    } else {
        printf("Command not recognized: %s\n", input);
    }
}

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SECRET_HOSTNAME "trusted.example.com"
#define LISTEN_PORT 8080
#define LISTEN_BACKLOG 5


// [MIA PASS] Perplexity: 1.08
// BAD - CWE-247
void example_1_bad(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in service;
    struct sockaddr_in serviceClient;
    int serviceClientLen;
    struct hostent *hostInfo;

    do {
        if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
            break;
        }
        wsaDataInit = TRUE;
        
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            break;
        }
        
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(LISTEN_PORT);
        
        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
            break;
        }
        
        if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
            break;
        }

        serviceClientLen = sizeof(serviceClient);
        client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen);
        if (client == INVALID_SOCKET) {
            break;
        }

        hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET);
        if (hostInfo == NULL || hostInfo->h_name == NULL) {
            break;
        }
        
        printf("Reverse DNS: %s\n", hostInfo->h_name);
        
        // FLAW: Using the reverse DNS of the client to determine whether to allow the connection
        if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) {
            printf("Access granted.\n");
        }

    } while (0);

    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    if (wsaDataInit) {
        WSACleanup();
    }
}

// GOOD - CWE-247
void example_1_good(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in service;
    struct sockaddr_in serviceClient;
    int serviceClientLen;

    do {
        if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
            break;
        }
        wsaDataInit = TRUE;
        
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            break;
        }
        
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(LISTEN_PORT);
        
        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
            break;
        }
        
        if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
            break;
        }

        serviceClientLen = sizeof(serviceClient);
        client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen);
        if (client == INVALID_SOCKET) {
            break;
        }

        // GOOD: Do not rely on DNS resolution for security decisions
        printf("Connection received from IP: %s\n", inet_ntoa(serviceClient.sin_addr));

        // Implement additional authentication or trust validation steps
        
    } while (0);

    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    if (wsaDataInit) {
        WSACleanup();
    }
}


// [MIA PASS] Perplexity: 1.09
// BAD - CWE-247
void example_2_bad(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET serverSock = INVALID_SOCKET;
    SOCKET clientSock = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    struct hostent *hostDetails;
    int clientAddrLen = sizeof(clientAddr);

    do {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            break;
        }
        wsaDataInit = TRUE;

        serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSock == INVALID_SOCKET) {
            break;
        }
        
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(LISTEN_PORT);

        if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            break;
        }

        if (listen(serverSock, LISTEN_BACKLOG) == SOCKET_ERROR) {
            break;
        }

        clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock == INVALID_SOCKET) {
            break;
        }

        hostDetails = gethostbyaddr((char*)&clientAddr.sin_addr, sizeof(clientAddr.sin_addr), AF_INET);
        if (hostDetails == NULL || hostDetails->h_name == NULL) {
            break;
        }

        printf("Client's Reverse DNS: %s\n", hostDetails->h_name);

        // FLAW: Relying on DNS for security decision
        if (strcmp(hostDetails->h_name, SECRET_HOSTNAME) == 0) {
            printf("Access granted based on DNS lookup.\n");
        }

    } while (0);

    if (clientSock != INVALID_SOCKET) {
        closesocket(clientSock);
    }
    if (serverSock != INVALID_SOCKET) {
        closesocket(serverSock);
    }
    if (wsaDataInit) {
        WSACleanup();
    }
}

// GOOD - CWE-247
void example_2_good(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET serverSock = INVALID_SOCKET;
    SOCKET clientSock = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    do {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            break;
        }
        wsaDataInit = TRUE;

        serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSock == INVALID_SOCKET) {
            break;
        }
        
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(LISTEN_PORT);

        if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            break;
        }

        if (listen(serverSock, LISTEN_BACKLOG) == SOCKET_ERROR) {
            break;
        }

        clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock == INVALID_SOCKET) {
            break;
        }

        printf("Client connected from IP: %s\n", inet_ntoa(clientAddr.sin_addr));

        // GOOD: Avoid making security decisions based solely on DNS information
        // Use IP-based whitelist or additional security checks

    } while (0);

    if (clientSock != INVALID_SOCKET) {
        closesocket(clientSock);
    }
    if (serverSock != INVALID_SOCKET) {
        closesocket(serverSock);
    }
    if (wsaDataInit) {
        WSACleanup();
    }
}

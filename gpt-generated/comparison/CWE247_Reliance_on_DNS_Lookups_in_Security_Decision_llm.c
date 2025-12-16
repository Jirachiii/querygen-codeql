#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>


// [LLM PASS]
// GOOD - 247
void example_1_good(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in service;
    struct sockaddr_in serviceClient;
    int serviceClientLen;
    char ipBuffer[INET_ADDRSTRLEN];

    do {
        if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
            break;
        }
        wsaDataInit = TRUE;

        listenSocket = socket(PF_INET, SOCK_STREAM, 0);
        if (listenSocket == INVALID_SOCKET) {
            break;
        }

        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(8080);

        if (SOCKET_ERROR == bind(listenSocket, (struct sockaddr*)&service, sizeof(service))) {
            break;
        }

        if (SOCKET_ERROR == listen(listenSocket, LISTEN_BACKLOG)) {
            break;
        }

        serviceClientLen = sizeof(serviceClient);
        client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen);
        if (client == INVALID_SOCKET) {
            break;
        }

        if (inet_ntop(AF_INET, &serviceClient.sin_addr, ipBuffer, INET_ADDRSTRLEN) != NULL) {
            printf("Client IP: %s\n", ipBuffer);
        }
        
        // GOOD: Don't rely on DNS; use network controls and further authentication
        // Assume some predefined list of allowed IPs in the system's firewall or configuration
        
    } while (0);

    if (client != INVALID_SOCKET) closesocket(client);
    if (listenSocket != INVALID_SOCKET) closesocket(listenSocket);
    if (wsaDataInit) WSACleanup();
}

// GOOD - 247
void example_2_good(void) {
    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    const char *reliableIP = "192.0.2.1"; // Pre-configured allowed IP

    do {
        if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
            break;
        }
        wsaDataInit = TRUE;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            break;
        }

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        inet_pton(AF_INET, reliableIP, &server.sin_addr);
        server.sin_port = htons(80);

        // Make connection decisions based on IP, not hostnames
        if (strcmp(reliableIP, "192.0.2.1") == 0) {
            printf("Connecting to trusted IP address.\n");
        } else {
            printf("Connection to non-trusted IP denied.\n");
        }
        
    } while (0);

    if (sock != INVALID_SOCKET) closesocket(sock);
    if (wsaDataInit) WSACleanup();
}

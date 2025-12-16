#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5


// [MIA PASS] Perplexity: 1.19
// BAD - 319
void example_1_bad(void) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;

    char password[100] = "";
    size_t passwordLen = 0;
    int recvResult;
    struct sockaddr_in service;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(TCP_PORT);

    if (bind(listenSocket, (struct sockaddr*) &service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    printf("Waiting for a connection...\n");
    acceptSocket = accept(listenSocket, NULL, NULL);
    if (acceptSocket == INVALID_SOCKET) {
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    recvResult = recv(acceptSocket, password, sizeof(password) - 1, 0);
    if (recvResult == SOCKET_ERROR || recvResult == 0) {
        closesocket(acceptSocket);
        closesocket(listenSocket);
        WSACleanup();
        return;
    }
    password[recvResult] = '\0'; // terminate password

    printf("Received password: %s\n", password);

    closesocket(acceptSocket);
    closesocket(listenSocket);
    WSACleanup();
}

// BAD - 319
void example_2_bad(void) {
    FILE *file = fopen("password.txt", "r");
    if (file == NULL) {
        printf("Unable to open file\n");
        return;
    }

    char password[100];
    fgets(password, sizeof(password), file);
    printf("Read password in plaintext: %s\n", password); // Exposing password

    fclose(file);
}


// [MIA PASS] Perplexity: 1.27
// GOOD - 319
void example_1_good(void) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    struct sockaddr_in addr;
    char password[100];

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());

    server = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(server, (struct sockaddr*)&addr, sizeof(addr));
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_read(ssl, password, sizeof(password));
    password[sizeof(password) - 1] = '\0';

    printf("Received password securely using SSL: %s\n", password);

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

// GOOD - 319
void example_2_good(void) {
    FILE *file = fopen("password.txt", "r");
    if (file == NULL) {
        printf("Unable to open file\n");
        return;
    }

    char encryptedPassword[256];
    fgets(encryptedPassword, sizeof(encryptedPassword), file);

    // Suppose decryptPassword is a function that decrypts the password
    // char* decryptPassword(const char* encrypted);
    // char* decryptedPassword = decryptPassword(encryptedPassword);

    // Simulating decryption with a static value for demonstration
    char decryptedPassword[100] = "DecryptedPass";

    printf("Decrypted password: %s\n", decryptedPassword);

    fclose(file);
}

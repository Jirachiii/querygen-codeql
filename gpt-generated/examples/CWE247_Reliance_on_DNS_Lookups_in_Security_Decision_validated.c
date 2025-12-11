#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_PORT 8080
#define LISTEN_BACKLOG 5
#define SECRET_HOSTNAME "trusted.example.com"

// BAD - CWE-247: Uses DNS information for security decisions in file operations
void fileAccess_bad(void) {
    FILE *file;
    struct hostent *hostInfo;
    struct sockaddr_in sa;
    char *hostname = "malicious.example.com";
    inet_pton(AF_INET, "192.168.1.1", &sa.sin_addr);

    // Potentially unsafe: DNS resolution is used to make a security decision
    hostInfo = gethostbyaddr((const void *)&sa.sin_addr, sizeof(sa.sin_addr), AF_INET);

    if (hostInfo != NULL && strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) {
        // Incorrect usage: Based on DNS lookup, decide to allow file deletion
        file = fopen("sensitive_data.txt", "w");
        if (file != NULL) {
            fprintf(file, "Clearing sensitive data.\n");
            fclose(file);
            printf("Sensitive file content deleted based on DNS verification.\n");
        }
    } else {
        printf("Access denied to sensitive file.\n");
    }
}

// GOOD - No reliance on DNS for security in file operations
void fileAccess_good(void) {
    FILE *file;

    // Use more reliable verification methods, not shown here
    int accessAllowed = 1; // Placeholder: secure method for access verification

    if (accessAllowed) {
        // Using correct decision mechanisms for access
        file = fopen("sensitive_data.txt", "w");
        if (file != NULL) {
            fprintf(file, "Clearing sensitive data under controlled logic.\n");
            fclose(file);
            printf("Sensitive file content securely cleared.\n");
        }
    } else {
        printf("Access denied to sensitive file.\n");
    }
}

// BAD - CWE-247: Uses DNS information for processing network input
void networkInput_bad(void) {
    int sockfd;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    struct hostent *hostInfo;
    char buffer[1024];

    // Network setup omitted for brevity
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(LISTEN_PORT);
    bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientAddr, &addrLen);

    // Potential vulnerability: DNS name used for decisions
    hostInfo = gethostbyaddr((const void *)&clientAddr.sin_addr.s_addr, sizeof(clientAddr.sin_addr.s_addr), AF_INET);

    if (hostInfo != NULL && strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) {
        printf("Network data from validated host: %s\n", buffer);
    } else {
        printf("Unknown host. Input not trusted.\n");
    }
    close(sockfd);
}

// GOOD - Use cryptographic or application-layer validation
void networkInput_good(void) {
    int sockfd;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    char buffer[1024];

    // Network setup omitted for brevity
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(LISTEN_PORT);
    bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientAddr, &addrLen);

    // Pretend we have a secure token verification mechanism
    int isVerified = 1; // Placeholder: assume a token in buffer

    if (isVerified) {
        printf("Network data verified: %s\n", buffer);
    } else {
        printf("Input could not be verified.\n");
    }
    close(sockfd);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

// BAD - CWE-273: Improper handling of privilege dropping in file I/O context.
void file_operations_bad(void) {
    int fd;
    char fileName[] = "/tmp/test_file.txt";
    char buffer[100];

    fd = open(fileName, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    // Simulate a privilege drop by changing UID
    seteuid(getuid());

    // Vulnerability: Not checking if seteuid succeeded
    read(fd, buffer, sizeof(buffer) - 1); // Read data without verifying privilege drop
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Read data: %s\n", buffer); // Potential unauthorized access

    close(fd);
}

// GOOD - Proper handling and checking of privilege dropping in file I/O context.
void file_operations_good(void) {
    int fd;
    char fileName[] = "/tmp/test_file.txt";
    char buffer[100];

    fd = open(fileName, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    // Attempt to drop privileges and check if it succeeds
    if (seteuid(getuid()) != 0) {
        perror("seteuid");
        close(fd);
        exit(1);
    }

    // Proceed only if privilege successfully dropped
    if (read(fd, buffer, sizeof(buffer) - 1) == -1) {
        perror("read");
        close(fd);
        exit(1);
    }

    buffer[sizeof(buffer) - 1] = '\0';
    printf("Read data: %s\n", buffer);

    close(fd);
}

// BAD - CWE-273: Improper checking in network operations context.
void network_operations_bad(void) {
    int sockfd;
    char buffer[256];
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(1);
    }

    // Simulate privilege drop without checking
    seteuid(getuid());

    // Vulnerable network read operation
    recv(sockfd, buffer, sizeof(buffer) - 1, 0);

    printf("Received data: %s\n", buffer); // Unauthorized access risk

    close(sockfd);
}

// GOOD - Proper checking of privilege drop in network operations context.
void network_operations_good(void) {
    int sockfd;
    char buffer[256];
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(1);
    }

    // Properly check the privilege drop attempt
    if (seteuid(getuid()) != 0) {
        perror("seteuid");
        close(sockfd);
        exit(1);
    }

    // Secure network read operation only if privilege drop is successful
    if (recv(sockfd, buffer, sizeof(buffer) - 1, 0) <= 0) {
        perror("recv");
        close(sockfd);
        exit(1);
    }

    printf("Received data: %s\n", buffer);

    close(sockfd);
}

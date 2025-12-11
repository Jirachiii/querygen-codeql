#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

// BAD - CWE-272: Using elevated privileges for file creation unnecessarily
void fileCreation_bad() {
    FILE *file;
    // Attempt to create a file in a protected system directory
    file = fopen("/etc/system_info.txt", "w");
    if (file == NULL) {
        perror("File creation failed");
    } else {
        fprintf(file, "System information");
        fclose(file);
    }
}

// GOOD - Least Privilege: Create file in user directory
void fileCreation_good() {
    FILE *file;
    // Safe location for personal user files
    file = fopen("user_info.txt", "w");
    if (file == NULL) {
        perror("File creation failed");
    } else {
        fprintf(file, "User information");
        fclose(file);
    }
}

// BAD - CWE-272: Using admin privileges to listen on common ports
void networkListen_bad() {
#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in service;
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("WSA Startup failed");
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        perror("Socket creation failed");
        WSACleanup();
        return;
    }

    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(80);  // Attempting to listen on a privileged port

    if (bind(sock, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        perror("Bind failed");
        closesocket(sock);
        WSACleanup();
        return;
    }

    printf("Listening on port 80\n");
    closesocket(sock);
    WSACleanup();
#endif
}

// GOOD - Least Privilege: Listen on unprivileged port
void networkListen_good() {
#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in service;
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("WSA Startup failed");
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        perror("Socket creation failed");
        WSACleanup();
        return;
    }

    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(8080);  // Using non-privileged port

    if (bind(sock, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        perror("Bind failed");
        closesocket(sock);
        WSACleanup();
        return;
    }

    printf("Listening on port 8080\n");
    closesocket(sock);
    WSACleanup();
#endif
}

int main(void) {
    // Call examples to avoid untranslated functions in the IDE
    fileCreation_bad();
    fileCreation_good();
    networkListen_bad();
    networkListen_good();

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")


// [MIA PASS] Perplexity: 1.15
// BAD - 15
void example_1_bad(void) {
    char *data;
    char dataBuffer[256] = "";
    data = dataBuffer;

    WSADATA wsaData;
    BOOL wsaDataInit = FALSE;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET acceptSocket = INVALID_SOCKET;
    struct sockaddr_in service;
    int recvResult;

    do {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
            break;
        }
        wsaDataInit = 1;
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            break;
        }
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(27015);
        if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
            break;
        }
        if (listen(listenSocket, 5) == SOCKET_ERROR) {
            break;
        }
        acceptSocket = accept(listenSocket, NULL, NULL);
        if (acceptSocket == INVALID_SOCKET) {
            break;
        }
        recvResult = recv(acceptSocket, data, 255, 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0) {
            break;
        }
        data[recvResult] = '\0';
    } while (0);

    if (acceptSocket != INVALID_SOCKET) {
        closesocket(acceptSocket);
    }
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    if (wsaDataInit) {
        WSACleanup();
    }

    // FLAW: Using potentially external data to set a system configuration
    if (!SetComputerNameA(data)) {
        printf("Failed to set computer name\n");
        exit(1);
    }
}

// BAD - 15
void example_2_bad(void) {
    char *data;
    char dataBuffer[256];
    data = dataBuffer;

    FILE *file = fopen("externalInput.txt", "r");
    if (file != NULL) {
        if (fgets(data, 256, file) == NULL) {
            fclose(file);
            return;
        }
        fclose(file);

        // FLAW: Use potentially unchecked user input to modify system settings
        if (!SetEnvironmentVariableA("NEW_VARIABLE", data)) {
            printf("Failed to set environment variable\n");
            exit(1);
        }
    }
}


// [MIA PASS] Perplexity: 1.36
// GOOD - 15
void example_1_good(void) {
    const char *configValue = "HardCodedValue";

    // Use a fixed, internal configuration value
    if (!SetComputerNameA(configValue)) {
        printf("Failed to set computer name\n");
        exit(1);
    }
}

// GOOD - 15
void example_2_good(void) {
    // Use a fixed, internal configuration for setting an environment variable
    if (!SetEnvironmentVariableA("NEW_VARIABLE", "FixedValue")) {
        printf("Failed to set environment variable\n");
        exit(1);
    }
}

int main() {
    // Run examples to demonstrate functionality
    example_1_good();
    example_2_good();

    return 0;
}

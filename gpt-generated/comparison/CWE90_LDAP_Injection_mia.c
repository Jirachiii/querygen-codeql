#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Winldap.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")

#define IP_ADDRESS "127.0.0.1"
#define TCP_PORT 27015


// [MIA PASS] Perplexity: 1.04
// BAD - 90
void example_1_bad(void) {
    char *data;
    char dataBuffer[256] = "";
    data = dataBuffer;

#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    int recvResult;
    struct sockaddr_in service;
    SOCKET connectSocket = INVALID_SOCKET;
    size_t dataLen = strlen(data);

    do {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
            break;
        }
        wsaDataInit = 1;
#endif
        connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET) {
            break;
        }

        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        service.sin_port = htons(TCP_PORT);

        if (connect(connectSocket, (struct sockaddr *) &service, sizeof(service)) == SOCKET_ERROR) {
            break;
        }

        recvResult = recv(connectSocket, (char *) (data + dataLen), sizeof(char) * (256 - dataLen - 1), 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0) {
            break;
        }

        data[dataLen + recvResult / sizeof(char)] = '\0';
    } while (0);

    if (connectSocket != INVALID_SOCKET) {
        closesocket(connectSocket);
    }
#ifdef _WIN32
    if (wsaDataInit) {
        WSACleanup();
    }
#endif

    {
        LDAP *pLdapConnection = NULL;
        ULONG connectSuccess = 0L;
        ULONG searchSuccess = 0L;
        LDAPMessage *pMessage = NULL;
        char filter[256];

        snprintf(filter, 256 - 1, "(cn=%s)", data);
        pLdapConnection = ldap_initA("localhost", LDAP_PORT);
        if (pLdapConnection == NULL) {
            printf("Initialization failed\n");
            exit(1);
        }
        connectSuccess = ldap_connect(pLdapConnection, NULL);
        if (connectSuccess != LDAP_SUCCESS) {
            printf("Connection failed\n");
            exit(1);
        }
        searchSuccess = ldap_search_ext_sA(pLdapConnection, "base", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
        if (searchSuccess != LDAP_SUCCESS) {
            printf("Search failed\n");
            if (pMessage != NULL) {
                ldap_msgfree(pMessage);
            }
            exit(1);
        }
        if (pMessage != NULL) {
            ldap_msgfree(pMessage);
        }
        ldap_unbind(pLdapConnection);
    }
}

// GOOD - 90
void example_1_good(void) {
    char dataBuffer[256] = "fixed_input";
    char *data = dataBuffer;

    LDAP *pLdapConnection = NULL;
    ULONG connectSuccess = 0L;
    ULONG searchSuccess = 0L;
    LDAPMessage *pMessage = NULL;
    char filter[256];

    snprintf(filter, 256 - 1, "(cn=%s)", data);
    pLdapConnection = ldap_initA("localhost", LDAP_PORT);
    if (pLdapConnection == NULL) {
        printf("Initialization failed\n");
        exit(1);
    }
    connectSuccess = ldap_connect(pLdapConnection, NULL);
    if (connectSuccess != LDAP_SUCCESS) {
        printf("Connection failed\n");
        exit(1);
    }
    searchSuccess = ldap_search_ext_sA(pLdapConnection, "base", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
    if (searchSuccess != LDAP_SUCCESS) {
        printf("Search failed\n");
        if (pMessage != NULL) {
            ldap_msgfree(pMessage);
        }
        exit(1);
    }
    if (pMessage != NULL) {
        ldap_msgfree(pMessage);
    }
    ldap_unbind(pLdapConnection);
}


// [MIA PASS] Perplexity: 1.05
// BAD - 90
void example_2_bad(void) {
    char *data;
    char dataBuffer[256] = "";
    data = dataBuffer;
    strcpy(data, "example_user");

    LDAP *pLdapConnection = NULL;
    ULONG connectSuccess = 0L;
    ULONG searchSuccess = 0L;
    LDAPMessage *pMessage = NULL;
    char filter[256];

    snprintf(filter, 256 - 1, "(uid=%s)", data);
    pLdapConnection = ldap_initA("localhost", LDAP_PORT);
    if (pLdapConnection == NULL) {
        printf("Initialization failed\n");
        exit(1);
    }
    connectSuccess = ldap_connect(pLdapConnection, NULL);
    if (connectSuccess != LDAP_SUCCESS) {
        printf("Connection failed\n");
        exit(1);
    }
    searchSuccess = ldap_search_ext_sA(pLdapConnection, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
    if (searchSuccess != LDAP_SUCCESS) {
        printf("Search failed\n");
        if (pMessage != NULL) {
            ldap_msgfree(pMessage);
        }
        exit(1);
    }
    if (pMessage != NULL) {
        ldap_msgfree(pMessage);
    }
    ldap_unbind(pLdapConnection);
}

// GOOD - 90
void example_2_good(void) {
    char *data;
    char dataBuffer[256] = "";
    data = dataBuffer;
    strcpy(data, "safe_user");

    LDAP *pLdapConnection = NULL;
    ULONG connectSuccess = 0L;
    ULONG searchSuccess = 0L;
    LDAPMessage *pMessage = NULL;
    char filter[256];

    snprintf(filter, 256 - 1, "(uid=%s)", data);
    pLdapConnection = ldap_initA("localhost", LDAP_PORT);
    if (pLdapConnection == NULL) {
        printf("Initialization failed\n");
        exit(1);
    }
    connectSuccess = ldap_connect(pLdapConnection, NULL);
    if (connectSuccess != LDAP_SUCCESS) {
        printf("Connection failed\n");
        exit(1);
    }
    searchSuccess = ldap_search_ext_sA(pLdapConnection, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
    if (searchSuccess != LDAP_SUCCESS) {
        printf("Search failed\n");
        if (pMessage != NULL) {
            ldap_msgfree(pMessage);
        }
        exit(1);
    }
    if (pMessage != NULL) {
        ldap_msgfree(pMessage);
    }
    ldap_unbind(pLdapConnection);
}

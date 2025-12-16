#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5


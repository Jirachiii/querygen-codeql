#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define POPEN _popen
#define PCLOSE _pclose
#else
#include <unistd.h>
#define POPEN popen
#define PCLOSE pclose
#endif

// Constants for network operations (used for illustration, not functional in standalone code)
#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"
#define INVALID_SOCKET -1
typedef int SOCKET;


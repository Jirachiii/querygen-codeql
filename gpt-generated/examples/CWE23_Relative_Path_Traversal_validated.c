#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#define CLOSE_SOCKET closesocket
#define BASEPATH L"C:\\safe_dir\\"
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#define CLOSE_SOCKET close
#define BASEPATH L"/safe_dir/"
#endif

#define FILENAME_MAX 260
#define SERVER_PORT 12345
#define BUFFER_SIZE 512

// BAD - CWE-23: Accepting paths via command line arguments without checks
void cmd_arg_bad(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return;
    }

    // POTENTIAL FLAW: Directly using command-line argument
    FILE *file = fopen(argv[1], "r");
    if (file) {
        char buffer[BUFFER_SIZE];
        size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, file);
        buffer[bytesRead] = '\0';
        printf("File content: %s\n", buffer);
        fclose(file);
    }
}

// GOOD - Validate command line arguments
void cmd_arg_good(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <safe_filename>\n", argv[0]);
        return;
    }

    // Construct a full path safely and validate
    char fullPath[FILENAME_MAX];
    snprintf(fullPath, FILENAME_MAX, "/safe_dir/%s", argv[1]);

    // Validate path input
    if (strstr(fullPath, "//") == NULL && strstr(fullPath, "..") == NULL) {
        FILE *file = fopen(fullPath, "r");
        if (file) {
            char buffer[BUFFER_SIZE];
            size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, file);
            buffer[bytesRead] = '\0';
            printf("File content: %s\n", buffer);
            fclose(file);
        }
    } else {
        printf("Potential path traversal detected!\n");
    }
}

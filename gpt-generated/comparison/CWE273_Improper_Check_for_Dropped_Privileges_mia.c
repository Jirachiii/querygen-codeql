#include <stdio.h>
#include <windows.h>

// Utility function for error logging
void logError(const char *message) {
    fprintf(stderr, "Error: %s - %ld\n", message, GetLastError());
}


// [MIA PASS] Perplexity: 1.17
// BAD - 273
void bad_example_1(void) {
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    hPipe = CreateNamedPipeA(
                "\\\\.\\pipe\\example_pipe_1",
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096,
                NMPWAIT_USE_DEFAULT_WAIT,
                NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        exit(1);
    }
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(hPipe);
        exit(1);
    }
    // FLAW: Failed to check the return value of ImpersonateNamedPipeClient
    ImpersonateNamedPipeClient(hPipe);
    printLine("Impersonated without checking");
    if (!RevertToSelf()) {
        exit(1);
    }
    CloseHandle(hPipe);
}

// BAD - 273
void bad_example_2(void) {
    if (ImpersonateSelf(SecurityImpersonation)) {
        // FLAW: Failed to check the return value of SetThreadToken
        SetThreadToken(NULL, NULL);
        printLine("Dropped privileges without checking");
        if (!RevertToSelf()) {
            exit(1);
        }
    }
}


// [MIA PASS] Perplexity: 1.04
// GOOD - 273
void good_example_1(void) {
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    hPipe = CreateNamedPipeA(
                "\\\\.\\pipe\\example_pipe_2",
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096,
                NMPWAIT_USE_DEFAULT_WAIT,
                NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        logError("CreateNamedPipeA failed");
        return;
    }
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(hPipe);
        logError("ConnectNamedPipe failed");
        return;
    }
    if (!ImpersonateNamedPipeClient(hPipe)) {
        logError("ImpersonateNamedPipeClient failed");
        CloseHandle(hPipe);
        return;
    }
    printLine("Impersonated successfully");
    if (!RevertToSelf()) {
        logError("RevertToSelf failed");
    }
    CloseHandle(hPipe);
}

// GOOD - 273
void good_example_2(void) {
    if (ImpersonateSelf(SecurityImpersonation)) {
        if (!SetThreadToken(NULL, NULL)) {
            logError("SetThreadToken failed");
            RevertToSelf();
            return;
        }
        printLine("Privileges dropped successfully");
        if (!RevertToSelf()) {
            logError("RevertToSelf failed");
        }
    } else {
        logError("ImpersonateSelf failed");
    }
}

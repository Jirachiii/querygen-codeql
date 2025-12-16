#include <stdio.h>
#include <string.h>
#include <windows.h>


// [MIA PASS] Perplexity: 1.37
// BAD - CWE-259
void example_1_bad(void) {
    char password[100] = "hardcoded_password"; // Hardcoded password
    char *username = "Admin";
    char *domain = "Domain";
    HANDLE pHandle;

    // Attempt login using hardcoded password
    if (LogonUserA(
                username,
                domain,
                password,
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &pHandle) != 0) {
        printf("User logged in successfully.\n");
        CloseHandle(pHandle);
    } else {
        printf("Unable to login.\n");
    }
}

// BAD - CWE-259
void example_2_bad(void) {
    #define SECRET_KEY "12345" // Hardcoded API key
    char *api_key = SECRET_KEY;

    // Hypothetical API call that uses hardcoded API key
    printf("Connecting with API key: %s\n", api_key);
}


// [MIA PASS] Perplexity: 1.15
// GOOD - CWE-259
void example_1_good(void) {
    char password[100];
    char *username = "Admin";
    char *domain = "Domain";
    HANDLE pHandle;

    // Obtain password from secure input, not hardcoded
    printf("Enter password: ");
    scanf("%99s", password);

    // Attempt login using securely obtained password
    if (LogonUserA(
                username,
                domain,
                password,
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &pHandle) != 0) {
        printf("User logged in successfully.\n");
        CloseHandle(pHandle);
    } else {
        printf("Unable to login.\n");
    }
}

// GOOD - CWE-259
void example_2_good(void) {
    char api_key[100];

    // Obtain the API key from user input instead of hardcoding it
    printf("Enter API key: ");
    scanf("%99s", api_key);

    // Hypothetical API call with user-provided API key
    printf("Connecting with API key: %s\n", api_key);
}

int main() {
    example_1_bad();
    example_1_good();
    example_2_bad();
    example_2_good();
    return 0;
}

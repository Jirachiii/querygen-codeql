#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <string.h>
#include <stdlib.h>

#define PASSWORD_INPUT_SIZE 256
#define MD5_SUM_SIZE 16 // Size for MD5
#define SHA256_SUM_SIZE 32 // Size for SHA-256

// Utility function to print messages
void printLine(const char *message) {
    printf("%s\n", message);
}


// [LLM PASS]
// BAD - 328
void example_1_bad(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char password[PASSWORD_INPUT_SIZE];
    UCHAR calcHash[MD5_SUM_SIZE];
    DWORD hashSize;
    char *replace;

    if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) {
        exit(1);
    }
    
    replace = strchr(password, '\r');
    if (replace) *replace = '\0';
    replace = strchr(password, '\n');
    if (replace) *replace = '\0';

    if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_FULL, 0)) {
        exit(1);
    }
    // FLAW: Use a reversible hash (MD5, though not actually reversible, is considered broken)
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    hashSize = MD5_SUM_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, calcHash, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    printLine("Hash calculated (BAD example)");

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - 328
void example_1_good(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char password[PASSWORD_INPUT_SIZE];
    UCHAR calcHash[SHA256_SUM_SIZE];
    DWORD hashSize;
    char *replace;

    if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) {
        exit(1);
    }
    
    replace = strchr(password, '\r');
    if (replace) *replace = '\0';
    replace = strchr(password, '\n');
    if (replace) *replace = '\0';

    if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_AES, 0)) {
        exit(1);
    }
    // FIX: Use a secure hash (SHA-256)
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    hashSize = SHA256_SUM_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, calcHash, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    printLine("Hash calculated (GOOD example)");

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}


// [LLM PASS]
// BAD - 328
void example_2_bad(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char password[PASSWORD_INPUT_SIZE];
    UCHAR calcHash[MD5_SUM_SIZE];
    DWORD hashSize;
    char *replace;

    if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) {
        exit(1);
    }
    
    replace = strchr(password, '\r');
    if (replace) *replace = '\0';
    replace = strchr(password, '\n');
    if (replace) *replace = '\0';

    if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_FULL, 0)) {
        exit(1);
    }
    // FLAW: Use a weak hash (MD5)
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    hashSize = MD5_SUM_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, calcHash, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    printLine("Hash calculated (BAD example 2)");

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - 328
void example_2_good(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char password[PASSWORD_INPUT_SIZE];
    UCHAR calcHash[SHA256_SUM_SIZE];
    DWORD hashSize;
    char *replace;

    if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) {
        exit(1);
    }
    
    replace = strchr(password, '\r');
    if (replace) *replace = '\0';
    replace = strchr(password, '\n');
    if (replace) *replace = '\0';

    if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_AES, 0)) {
        exit(1);
    }
    // FIX: Use a secure hash (SHA-256)
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }
    hashSize = SHA256_SUM_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, calcHash, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    printLine("Hash calculated (GOOD example 2)");

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

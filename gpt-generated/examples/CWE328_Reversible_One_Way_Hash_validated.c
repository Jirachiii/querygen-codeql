#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define PASSWORD_INPUT_SIZE 128
#define MD2_SUM_SIZE 16

// BAD - CWE-328: Uses a reversible hash (MD2) for hashing user passwords read from a file
void file_hashing_bad() {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    FILE *inputFile = fopen("user_passwords.txt", "r");
    char password[PASSWORD_INPUT_SIZE];
    UCHAR storedHash[MD2_SUM_SIZE], computedHash[MD2_SUM_SIZE];
    DWORD hashSize;
    size_t i;

    if (!inputFile) {
        perror("Failed to open file");
        return;
    }

    // Read stored hash from the file
    for (i = 0; i < MD2_SUM_SIZE; i++) {
        unsigned int byte;
        if (fscanf(inputFile, "%02x", &byte) != 1) {
            fclose(inputFile);
            return;
        }
        storedHash[i] = (UCHAR)byte;
    }

    fclose(inputFile);

    // Get user password from stdin
    printf("Enter password: ");
    if (!fgets(password, PASSWORD_INPUT_SIZE, stdin)) {
        return;
    }

    // Strip newline
    char *newLine = strchr(password, '\n');
    if (newLine) *newLine = '\0';

    // Initialize cryptographic provider and MD2 hash object
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) ||
        !CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) {
        return;
    }

    // Hash the password
    CryptHashData(hHash, (BYTE *)password, strlen(password), 0);
    hashSize = MD2_SUM_SIZE;
    CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &hashSize, 0);

    // Compare the hashes
    if (memcmp(storedHash, computedHash, MD2_SUM_SIZE) == 0) {
        printf("Password is correct\n");
    } else {
        printf("Password is incorrect\n");
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - Replaces MD2 with a strong hash (SHA-256) for user password hashing
void file_hashing_good() {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    FILE *inputFile = fopen("user_passwords.txt", "r");
    char password[PASSWORD_INPUT_SIZE];
    BYTE storedHash[32], computedHash[32]; // SHA-256 produces 32 bytes hash
    DWORD hashSize;
    size_t i;

    if (!inputFile) {
        perror("Failed to open file");
        return;
    }

    // Read stored hash from the file
    for (i = 0; i < 32; i++) {
        unsigned int byte;
        if (fscanf(inputFile, "%02x", &byte) != 1) {
            fclose(inputFile);
            return;
        }
        storedHash[i] = (BYTE)byte;
    }

    fclose(inputFile);

    // Get user password from stdin
    printf("Enter password: ");
    if (!fgets(password, PASSWORD_INPUT_SIZE, stdin)) {
        return;
    }

    // Strip newline
    char *newLine = strchr(password, '\n');
    if (newLine) *newLine = '\0';

    // Initialize cryptographic provider and SHA-256 hash object
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        return;
    }

    // Hash the password
    CryptHashData(hHash, (BYTE *)password, strlen(password), 0);
    hashSize = 32; // SHA-256 hash size
    CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &hashSize, 0);

    // Compare the hashes
    if (memcmp(storedHash, computedHash, hashSize) == 0) {
        printf("Password is correct\n");
    } else {
        printf("Password is incorrect\n");
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// BAD - CWE-328: Uses MD4 hash (also reversible) for hashing credentials received over network
void network_hashing_bad() {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char credentials[PASSWORD_INPUT_SIZE] = "user:examplePassword"; // Sketchy network receive simulation
    UCHAR storedHash[16]; // MD4 produces a 16-byte hash
    UCHAR computedHash[16];
    DWORD hashSize;

    // Hash received credentials with MD4
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) ||
        !CryptCreateHash(hCryptProv, CALG_MD4, 0, 0, &hHash)) {
        return;
    }

    CryptHashData(hHash, (BYTE *)credentials, strlen(credentials), 0);
    hashSize = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &hashSize, 0);

    // Compare with stored hash for credentials
    memcpy(storedHash, "\xde\xad\xbe\xef", 16); // Placeholder hash comparison

    if (memcmp(storedHash, computedHash, 16) == 0) {
        printf("Access granted\n");
    } else {
        printf("Access denied\n");
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - Utilizes SHA-256 hash for network-received credentials
void network_hashing_good() {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    char credentials[PASSWORD_INPUT_SIZE] = "user:examplePassword"; // Secure network receive simulation
    BYTE storedHash[32], computedHash[32]; // SHA-256 hash size
    DWORD hashSize;

    // Hash credentials securely with SHA-256
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        return;
    }

    CryptHashData(hHash, (BYTE *)credentials, strlen(credentials), 0);
    hashSize = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &hashSize, 0);

    // Compare with stored safe hash for credentials
    memcpy(storedHash, "\xde\xad\xbe\xef", 32); // Placeholder hash comparison

    if (memcmp(storedHash, computedHash, hashSize) == 0) {
        printf("Access granted\n");
    } else {
        printf("Access denied\n");
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

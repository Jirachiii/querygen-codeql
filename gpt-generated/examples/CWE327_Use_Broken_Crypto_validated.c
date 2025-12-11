#include <windows.h>
#include <stdio.h>
#include <string.h>

// BAD - CWE-327: Uses MD5 for hashing, which is considered weak
void bad_example_1(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char buffer[128];
    char password[128];
    DWORD bufferLen = sizeof(buffer) - 1;

    // Prompt user for input
    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("fgets() failed\n");
        return;
    }

    // Remove newline character if present
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("Error in acquiring cryptographic context\n");
        return;
    }

    // Create hash object with MD5 (weak)
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        printf("Error in creating hash\n");
        return;
    }

    // Hash the password
    if (!CryptHashData(hHash, (BYTE *)password, strlen(password), 0)) {
        printf("Error in hashing password\n");
        return;
    }

    // Derive an RC2 key from the hashed password (also weak)
    if (!CryptDeriveKey(hCryptProv, CALG_RC2, hHash, 0, &hKey)) {
        printf("Error in deriving key\n");
        return;
    }

    strcpy(buffer, "Sensitive data");
    // Decrypt the buffer (simulating operation)
    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE *)buffer, &bufferLen)) {
        printf("Error in decryption\n");
        return;
    }

    printf("Decrypted data: %s\n", buffer);

    // Cleanup
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}

// GOOD - Uses a strong hashing algorithm (SHA-256) and AES for encryption/decryption
void good_example_1(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char buffer[128];
    char password[128];
    DWORD bufferLen = sizeof(buffer) - 1;

    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("fgets() failed\n");
        return;
    }

    // Remove newline character
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
        printf("Error in acquiring cryptographic context\n");
        return;
    }

    // Create hash object with SHA-256 (strong)
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error in creating hash\n");
        return;
    }

    // Hash the password
    if (!CryptHashData(hHash, (BYTE *)password, strlen(password), 0)) {
        printf("Error in hashing password\n");
        return;
    }

    // Derive an AES key from the hashed password (strong)
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Error in deriving key\n");
        return;
    }

    strcpy(buffer, "Sensitive data");
    // Decrypt the buffer (no actual decryption done here)
    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE *)buffer, &bufferLen)) {
        printf("Error in decryption\n");
        return;
    }

    printf("Decrypted data: %s\n", buffer);

    // Cleanup
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}

// BAD - CWE-327: Uses DES algorithm, which is considered weak
void bad_example_2(void) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    char plaintext[128] = "Confidential information";
    BYTE encryptedData[128];
    DWORD encryptedDataLen = sizeof(encryptedData);

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        printf("Error acquiring context\n");
        return;
    }

    HCRYPTKEY hGeneratedKey;
    if (!CryptGenKey(hProv, CALG_DES, CRYPT_EXPORTABLE, &hGeneratedKey)) {
        printf("Error generating key\n");
        return;
    }

    memcpy(encryptedData, plaintext, sizeof(plaintext));

    // Encrypt using DES
    if (!CryptEncrypt(hGeneratedKey, 0, TRUE, 0, encryptedData, &encryptedDataLen, sizeof(encryptedData))) {
        printf("Error encrypting data\n");
        return;
    }

    printf("Encrypted data (DES): %.*s\n", encryptedDataLen, encryptedData);

    // Cleanup
    if (hGeneratedKey) CryptDestroyKey(hGeneratedKey);
    if (hProv) CryptReleaseContext(hProv, 0);
}

// GOOD - Uses AES for encryption, which is strong and recommended
void good_example_2(void) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    char plaintext[128] = "Confidential information";
    BYTE encryptedData[128];
    DWORD encryptedDataLen = sizeof(encryptedData);

    // Acquire cryptographic context with AES provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 0)) {
        printf("Error acquiring context\n");
        return;
    }

    // Generate an AES key
    if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        printf("Error generating key\n");
        return;
    }

    memcpy(encryptedData, plaintext, sizeof(plaintext));

    // Encrypt using AES
    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &encryptedDataLen, sizeof(encryptedData))) {
        printf("Error encrypting data\n");
        return;
    }

    printf("Encrypted data (AES): %.*s\n", encryptedDataLen, encryptedData);

    // Cleanup
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
}

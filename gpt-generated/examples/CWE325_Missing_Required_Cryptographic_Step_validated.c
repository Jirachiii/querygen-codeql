#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

// BAD - CWE-325: Missing cryptographic key derivation with user input
void user_input_encryption_bad() {
    BYTE data[128];
    DWORD dataLen;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    
    // Read input from user
    printf("Enter secret data: ");
    fgets((char*)data, sizeof(data), stdin);
    dataLen = strlen((char*)data);

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }
    
    // Create hash
    if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    
    // Hash the data (user input)
    if (!CryptHashData(hHash, data, dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    
    // FLAW: Missing CryptDeriveKey step, using a NULL key
    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data))) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    
    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - Proper encryption with derived key from user input
void user_input_encryption_good() {
    BYTE data[128];
    DWORD dataLen;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    
    // Read input from user
    printf("Enter secret data: ");
    fgets((char*)data, sizeof(data), stdin);
    dataLen = strlen((char*)data);

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }
    
    // Create hash
    if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    
    // Hash the data (user input)
    if (!CryptHashData(hHash, data, dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    
    // Correct step: derive a key from the hash
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data))) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Clean up
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// BAD - CWE-325: Missing cryptographic key derivation during file I/O
void file_io_encryption_bad(const char *filename) {
    BYTE buffer[256] = {0};
    DWORD bytesRead;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    FILE *file = fopen(filename, "rb");

    if (!file) {
        return;
    }
    
    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(file);
        return;
    }

    // Create hash
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        fclose(file);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Read data from file
    bytesRead = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    // Hash the data from file
    if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // FLAW: Missing CryptDeriveKey step, using a NULL key
    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bytesRead, sizeof(buffer))) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - Proper encryption with derived key during file I/O
void file_io_encryption_good(const char *filename) {
    BYTE buffer[256] = {0};
    DWORD bytesRead;
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    FILE *file = fopen(filename, "rb");

    if (!file) {
        return;
    }
    
    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(file);
        return;
    }

    // Create hash
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        fclose(file);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Read data from file
    bytesRead = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    // Hash the data from the file
    if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Correct step: derive a key from the hash
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bytesRead, sizeof(buffer))) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // Clean up
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

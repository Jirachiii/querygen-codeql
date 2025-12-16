#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>


// [LLM PASS]
// GOOD - 327
void example_1_good(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char password[100];
    size_t passwordLen;
    char data[100] = "Sensitive data";

    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Error reading password.\n");
        return;
    }

    passwordLen = strlen(password);
    if (passwordLen > 0) {
        password[passwordLen - 1] = '\0';
    }

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            printf("Error acquiring cryptographic context.\n");
            return;
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error creating hash.\n");
        return;
    }

    if (!CryptHashData(hHash, (BYTE*)password, passwordLen, 0)) {
        printf("Error hashing password.\n");
        return;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { // Using AES which is strong
        printf("Error deriving key.\n");
        return;
    }

    DWORD dataLen = strlen(data);
    if (!CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)data, &dataLen, sizeof(data))) {
        printf("Error encrypting data.\n");
        return;
    }

    printf("Encrypted data: %s\n", data);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

// GOOD - 327
void example_2_good(void) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char key[] = "ComplexSecureKey";
    BYTE data[] = "Sensitive data";

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            printf("Error acquiring cryptographic context.\n");
            return;
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error creating hash.\n");
        return;
    }

    if (!CryptHashData(hHash, (BYTE*)key, strlen(key), 0)) {
        printf("Error hashing key.\n");
        return;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { // Using AES which is strong
        printf("Error deriving key.\n");
        return;
    }

    DWORD dataLen = sizeof(data);
    if (!CryptEncrypt(hKey, 0, TRUE, 0, data, &dataLen, sizeof(data))) {
        printf("Error encrypting data.\n");
        return;
    }

    printf("Encrypted data: %s\n", data);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
}

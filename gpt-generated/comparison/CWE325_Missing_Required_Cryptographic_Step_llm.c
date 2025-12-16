#include <stdio.h>
#include <string.h>
#include <windows.h>


// [LLM PASS]
// BAD - 325
void example_1_bad(void) {
    BYTE payload[100];
    DWORD payloadLen = strlen("SensitiveData");
    HCRYPTPROV hCryptProv = (HCRYPTPROV)NULL;
    HCRYPTHASH hHash = (HCRYPTHASH)NULL;
    HCRYPTKEY hKey = (HCRYPTKEY)NULL;
    char hashData[100] = "RandomHashInput";

    memcpy(payload, "SensitiveData", payloadLen);

    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        return;
    }
    if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    // FLAW: Missing CryptDeriveKey step
    if(!CryptEncrypt(hKey, 0, TRUE, 0, payload, &payloadLen, sizeof(payload))) {
        printf("Encryption failed.\n");
    }

    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}

// GOOD - 325
void example_1_good(void) {
    BYTE payload[100];
    DWORD payloadLen = strlen("SensitiveData");
    HCRYPTPROV hCryptProv = (HCRYPTPROV)NULL;
    HCRYPTHASH hHash = (HCRYPTHASH)NULL;
    HCRYPTKEY hKey = (HCRYPTKEY)NULL;
    char hashData[100] = "RandomHashInput";

    memcpy(payload, "SensitiveData", payloadLen);

    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        return;
    }
    if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }
    if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return;
    }

    if(CryptEncrypt(hKey, 0, TRUE, 0, payload, &payloadLen, sizeof(payload))) {
        printf("Encrypted data: ");
        for(DWORD i = 0; i < payloadLen; i++) {
            printf("%02x", payload[i]);
        }
        printf("\n");
    }

    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}


// [LLM PASS]
// BAD - 325
void example_2_bad(void) {
    BYTE buffer[128];
    DWORD bufferLen = sizeof(buffer);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    char dataToHash[] = "SomeDataToHash";

    if(!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        return;
    }
    if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return;
    }
    if(!CryptHashData(hHash, (BYTE*)dataToHash, strlen(dataToHash), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // FLAW: Did not derive a key before encryption
    if(!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bufferLen, sizeof(buffer))) {
        printf("Encryption failed due to missing key derivation.\n");
    }

    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}

// GOOD - 325
void example_2_good(void) {
    BYTE buffer[128];
    DWORD bufferLen = sizeof(buffer);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    char dataToHash[] = "SomeDataToHash";

    if(!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        return;
    }
    if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return;
    }
    if(!CryptHashData(hHash, (BYTE*)dataToHash, strlen(dataToHash), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    if(!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    if(CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bufferLen, sizeof(buffer))) {
        printf("Encrypted data: ");
        for(DWORD i = 0; i < bufferLen; i++) {
            printf("%02x", buffer[i]);
        }
        printf("\n");
    }

    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}

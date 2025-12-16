#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>


// [MIA PASS] Perplexity: 1.03
// BAD - 327
void example_1_bad(void)
{
    FILE *pFile;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char password[100];
    size_t passwordLen;
    char toBeDecrypted[100];
    DWORD toBeDecryptedLen = sizeof(toBeDecrypted) - 1;

    printf("Enter the password: ");
    if (fgets(password, 100, stdin) == NULL)
    {
        printf("fgets() failed\n");
        password[0] = '\0';
    }

    passwordLen = strlen(password);
    if (passwordLen > 0)
    {
        password[passwordLen - 1] = '\0';
    }

    pFile = fopen("encrypted.txt", "rb");
    if (pFile == NULL)
    {
        exit(1);
    }
    if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
    {
        fclose(pFile);
        exit(1);
    }
    toBeDecrypted[99] = '\0';

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0))
    {
        if (!CryptAcquireContext(&hCryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        {
            printf("Error in acquiring cryptographic context\n");
            exit(1);
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
    {
        printf("Error in creating hash\n");
        exit(1);
    }

    if (!CryptHashData(hHash, (BYTE *)password, passwordLen, 0))
    {
        printf("Error in hashing password\n");
        exit(1);
    }

    // FLAW: Use of broken RC2 algorithm
    if (!CryptDeriveKey(hCryptProv, CALG_RC2, hHash, 0, &hKey))
    {
        printf("Error in CryptDeriveKey\n");
        exit(1);
    }

    if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
    {
        printf("Error in decryption\n");
        exit(1);
    }
    toBeDecrypted[toBeDecryptedLen] = '\0';
    printf("%s\n", toBeDecrypted);

    if (hKey)
    {
        CryptDestroyKey(hKey);
    }
    if (hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }
    if (pFile)
    {
        fclose(pFile);
    }
}

// BAD - 327
void example_2_bad(void)
{
    FILE *pFile;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char password[100];
    size_t passwordLen;
    char toBeDecrypted[100];
    DWORD toBeDecryptedLen = sizeof(toBeDecrypted) - 1;

    printf("Enter the password: ");
    if (fgets(password, 100, stdin) == NULL)
    {
        printf("fgets() failed\n");
        password[0] = '\0';
    }

    passwordLen = strlen(password);
    if (passwordLen > 0)
    {
        password[passwordLen - 1] = '\0';
    }

    pFile = fopen("encrypted_des.txt", "rb");
    if (pFile == NULL)
    {
        exit(1);
    }
    if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
    {
        fclose(pFile);
        exit(1);
    }
    toBeDecrypted[99] = '\0';

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0))
    {
        if (!CryptAcquireContext(&hCryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        {
            printf("Error in acquiring cryptographic context\n");
            exit(1);
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash))
    {
        printf("Error in creating hash\n");
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE *)password, passwordLen, 0))
    {
        printf("Error in hashing password\n");
        exit(1);
    }

    // FLAW: Use of broken DES algorithm
    if (!CryptDeriveKey(hCryptProv, CALG_DES, hHash, 0, &hKey))
    {
        printf("Error in CryptDeriveKey\n");
        exit(1);
    }

    if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
    {
        printf("Error in decryption\n");
        exit(1);
    }
    toBeDecrypted[toBeDecryptedLen] = '\0';
    printf("%s\n", toBeDecrypted);

    if (hKey)
    {
        CryptDestroyKey(hKey);
    }
    if (hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }
    if (pFile)
    {
        fclose(pFile);
    }
}


// [MIA PASS] Perplexity: 1.01
// GOOD - 327
void example_1_good(void)
{
    FILE *pFile;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char password[100];
    size_t passwordLen;
    char toBeDecrypted[100];
    DWORD toBeDecryptedLen = sizeof(toBeDecrypted) - 1;

    printf("Enter the password: ");
    if (fgets(password, 100, stdin) == NULL)
    {
        printf("fgets() failed\n");
        password[0] = '\0';
    }

    passwordLen = strlen(password);
    if (passwordLen > 0)
    {
        password[passwordLen - 1] = '\0';
    }

    pFile = fopen("encrypted_aes.txt", "rb");
    if (pFile == NULL)
    {
        exit(1);
    }
    if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
    {
        fclose(pFile);
        exit(1);
    }
    toBeDecrypted[99] = '\0';

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
    {
        if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
        {
            printf("Error in acquiring cryptographic context\n");
            exit(1);
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
    {
        printf("Error in creating hash\n");
        exit(1);
    }

    if (!CryptHashData(hHash, (BYTE *)password, passwordLen, 0))
    {
        printf("Error in hashing password\n");
        exit(1);
    }

    // FIX: Use strong AES algorithm
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
    {
        printf("Error in CryptDeriveKey\n");
        exit(1);
    }

    if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
    {
        printf("Error in decryption\n");
        exit(1);
    }
    toBeDecrypted[toBeDecryptedLen] = '\0';
    printf("%s\n", toBeDecrypted);

    if (hKey)
    {
        CryptDestroyKey(hKey);
    }
    if (hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }
    if (pFile)
    {
        fclose(pFile);
    }
}

// GOOD - 327
void example_2_good(void)
{
    FILE *pFile;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    char password[100];
    size_t passwordLen;
    char toBeDecrypted[100];
    DWORD toBeDecryptedLen = sizeof(toBeDecrypted) - 1;

    printf("Enter the password: ");
    if (fgets(password, 100, stdin) == NULL)
    {
        printf("fgets() failed\n");
        password[0] = '\0';
    }

    passwordLen = strlen(password);
    if (passwordLen > 0)
    {
        password[passwordLen - 1] = '\0';
    }

    pFile = fopen("encrypted_aes256.txt", "rb");
    if (pFile == NULL)
    {
        exit(1);
    }
    if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100)
    {
        fclose(pFile);
        exit(1);
    }
    toBeDecrypted[99] = '\0';

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
    {
        if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
        {
            printf("Error in acquiring cryptographic context\n");
            exit(1);
        }
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
    {
        printf("Error in creating hash\n");
        exit(1);
    }

    if (!CryptHashData(hHash, (BYTE *)password, passwordLen, 0))
    {
        printf("Error in hashing password\n");
        exit(1);
    }

    // FIX: Use strong AES-256 algorithm
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
    {
        printf("Error in CryptDeriveKey\n");
        exit(1);
    }

    if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen))
    {
        printf("Error in decryption\n");
        exit(1);
    }
    toBeDecrypted[toBeDecryptedLen] = '\0';
    printf("%s\n", toBeDecrypted);

    if (hKey)
    {
        CryptDestroyKey(hKey);
    }
    if (hHash)
    {
        CryptDestroyHash(hHash);
    }
    if (hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }
    if (pFile)
    {
        fclose(pFile);
    }
}

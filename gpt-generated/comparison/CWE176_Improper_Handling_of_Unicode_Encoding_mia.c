#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>


// [MIA PASS] Perplexity: 1.15
// BAD - 176
void example_1_bad(void) {
    wchar_t *data = L"Example Text With Unicode ☃";
    char convertedText[20] = "";
    int requiredSize;

    requiredSize = WideCharToMultiByte(CP_ACP, 0, data, -1, convertedText, 0, NULL, NULL);
    // POTENTIAL FLAW: Do not check if the destination buffer is large enough
    WideCharToMultiByte(CP_ACP, 0, data, -1, convertedText, requiredSize, NULL, NULL);

    printf("Converted Text: %s\n", convertedText);
}

// GOOD - 176
void example_1_good(void) {
    wchar_t *data = L"Example Text With Unicode ☃";
    int requiredSize = WideCharToMultiByte(CP_ACP, 0, data, -1, NULL, 0, NULL, NULL);
    
    if (requiredSize > 0) {
        char *convertedText = (char *)malloc(requiredSize);

        if (convertedText != NULL) {
            WideCharToMultiByte(CP_ACP, 0, data, -1, convertedText, requiredSize, NULL, NULL);
            printf("Converted Text: %s\n", convertedText);
            free(convertedText);
        }
    }
}


// [MIA PASS] Perplexity: 1.23
// BAD - 176
void example_2_bad(void) {
    wchar_t *utf16Data = L"🚀 Rocket Unicode";
    char convertedStr[5]; // Intentionally too small buffer
    int result;

    result = WideCharToMultiByte(CP_UTF8, 0, utf16Data, -1, convertedStr, sizeof(convertedStr), NULL, NULL);
    
    // POTENTIAL FLAW: Ignoring result and potential buffer overflow
    if (result > 0) {
        printf("Converted String: %s\n", convertedStr);
    }
}

// GOOD - 176
void example_2_good(void) {
    wchar_t *utf16Data = L"🚀 Rocket Unicode";
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, utf16Data, -1, NULL, 0, NULL, NULL);

    if (bufferSize > 0) {
        char *convertedStr = (char *)malloc(bufferSize);

        if (convertedStr != NULL) {
            int result = WideCharToMultiByte(CP_UTF8, 0, utf16Data, -1, convertedStr, bufferSize, NULL, NULL);
            
            if (result > 0) {
                printf("Converted String: %s\n", convertedStr);
            }

            free(convertedStr);
        }
    }
}

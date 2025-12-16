#include <stdio.h>
#include <string.h>
#include <windows.h>


// [MIA PASS] Perplexity: 1.33
// BAD - 226
void example_1_bad(void) {
    char sensitiveData[50] = "SecretToken12345";
    printf("Using sensitive data in operation...\n");
    // Hypothetical use of sensitiveData
    // FLAW: Release sensitive data without clearing it
}

// GOOD - 226
void example_1_good(void) {
    char sensitiveData[50] = "SecretToken12345";
    printf("Using sensitive data in operation...\n");
    // Hypothetical use of sensitiveData
    // FIX: Properly clear sensitive data before releasing it
    SecureZeroMemory(sensitiveData, sizeof(sensitiveData));
}


// [MIA PASS] Perplexity: 1.48
// BAD - 226
void example_2_bad(void) {
    char apiKey[] = "1234567890abcdef";
    processDataWithApiKey(apiKey); // Hypothetical function using the API key
    // FLAW: No attempt to clear sensitive API key data
}

// GOOD - 226
void example_2_good(void) {
    char apiKey[] = "1234567890abcdef";
    processDataWithApiKey(apiKey); // Hypothetical function using the API key
    // FIX: Clear sensitive API key data before releasing memory
    memset(apiKey, 0, sizeof(apiKey));
}

// Hypothetical function definitions
void processDataWithApiKey(const char* key) {
    printf("Processing data with API key: %s\n", key);
    // Simulating API key use
}

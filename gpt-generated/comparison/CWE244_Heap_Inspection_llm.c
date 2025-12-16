#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>


// [LLM PASS]
// BAD - 244
void example_1_bad(void) 
{
    char *sensitiveData = (char *)malloc(128 * sizeof(char));
    if (sensitiveData == NULL) {exit(-1);}
    strcpy(sensitiveData, "SensitivePassword123"); // Simulating reading sensitive data

    // Use sensitive data
    printf("Using sensitive data: %s\n", sensitiveData);

    // FLAW: Reallocating without clearing the original memory area
    sensitiveData = realloc(sensitiveData, 256 * sizeof(char));
    if (sensitiveData == NULL) {exit(-1);}
    
    strcpy(sensitiveData, "Generic Information");
    printf("%s\n", sensitiveData);

    free(sensitiveData);
}

// GOOD - 244
void example_1_good(void) 
{
    char *sensitiveData = (char *)malloc(128 * sizeof(char));
    if (sensitiveData == NULL) {exit(-1);}
    strcpy(sensitiveData, "SensitivePassword123"); // Simulating reading sensitive data

    // Use sensitive data
    printf("Using sensitive data: %s\n", sensitiveData);

    // Properly clear sensitive information before reallocating
    SecureZeroMemory(sensitiveData, 128 * sizeof(char));
    sensitiveData = realloc(sensitiveData, 256 * sizeof(char));
    if (sensitiveData == NULL) {exit(-1);}
    
    strcpy(sensitiveData, "Generic Information");
    printf("%s\n", sensitiveData);

    free(sensitiveData);
}


// [LLM PASS]
// BAD - 244
void example_2_bad(void) 
{
    char *buffer = (char *)malloc(50 * sizeof(char));
    if (buffer == NULL) {exit(-1);}
    strcpy(buffer, "VerySecret1234"); // Simulate loading a secret

    // FLAW: Performing operations without clearing the buffer afterwards
    printf("Process secret data: %s\n", buffer);
    
    buffer = realloc(buffer, 100 * sizeof(char));
    if (buffer == NULL) {exit(-1);}
    
    // The original secret remains in memory here
    strcpy(buffer, "Normal Data");
    printf("%s\n", buffer);

    free(buffer);
}

// GOOD - 244
void example_2_good(void) 
{
    char *buffer = (char *)malloc(50 * sizeof(char));
    if (buffer == NULL) {exit(-1);}
    strcpy(buffer, "VerySecret1234"); // Simulate loading a secret

    // Correct way to clear sensitive data
    printf("Process secret data: %s\n", buffer);
    SecureZeroMemory(buffer, 50 * sizeof(char));

    buffer = realloc(buffer, 100 * sizeof(char));
    if (buffer == NULL) {exit(-1);}
    
    strcpy(buffer, "Normal Data");
    printf("%s\n", buffer);

    free(buffer);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


// [MIA PASS] Perplexity: 1.31
// BAD - 126
void example_1_bad(void) {
    char *data = (char *)malloc(10);
    if (data == NULL) exit(1);
    strcpy(data, "HelloWorld");
    
    char buffer[5];
    /* POTENTIAL FLAW: Buffer over-read if the length of data is greater than the length of buffer */
    for (int i = 0; i < 10; i++) {
        buffer[i] = data[i];
    }

    buffer[4] = '\0'; // null terminate
    printf("%s\n", buffer);
    free(data);
}

// GOOD - 126
void example_1_good(void) {
    char *data = (char *)malloc(10);
    if (data == NULL) exit(1);
    strcpy(data, "Hello");

    char buffer[10];
    /* SAFE: Use strncpy to ensure no over-read happens */
    strncpy(buffer, data, 9);
    buffer[9] = '\0'; // Ensure the buffer is null terminated

    printf("%s\n", buffer);
    free(data);
}


// [MIA PASS] Perplexity: 1.03
// BAD - 126
void example_2_bad(void) {
    wchar_t *data = (wchar_t *)malloc(5 * sizeof(wchar_t));
    if (data == NULL) exit(1);
    wcscpy(data, L"ABCDE");

    wchar_t dest[3];
    /* POTENTIAL FLAW: Buffer over-read if the length of data is greater than the length of dest */
    for (int i = 0; i < 5; i++) {
        dest[i] = data[i];
    }

    dest[2] = L'\0'; // null terminate
    wprintf(L"%ls\n", dest);
    free(data);
}

// GOOD - 126
void example_2_good(void) {
    wchar_t *data = (wchar_t *)malloc(5 * sizeof(wchar_t));
    if (data == NULL) exit(1);
    wcscpy(data, L"AB");

    wchar_t dest[5];
    /* SAFE: Use wcsncpy to ensure no over-read happens */
    wcsncpy(dest, data, 4);
    dest[4] = L'\0'; // Ensure the buffer is null terminated

    wprintf(L"%ls\n", dest);
    free(data);
}

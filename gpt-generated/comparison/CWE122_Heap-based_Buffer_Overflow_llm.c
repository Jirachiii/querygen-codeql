#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


// [LLM PASS]
// BAD - 122
void example_1_bad(void) {
    char *data;
    data = (char *)malloc(100 * sizeof(char));
    if (data == NULL) return; // Check for null to avoid dereference
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100 - 1); // fill with 'A's
    data[100 - 1] = '\0'; // null terminate

    char dest[50] = "";
    /* POTENTIAL FLAW: Possible buffer overflow if data is larger than dest */
    strncpy(dest, data, strlen(data));
    dest[50 - 1] = '\0'; // Ensure the destination buffer is null terminated
    printf("%s\n", dest);
    free(data);
}

// GOOD - 122
void example_1_good(void) {
    char *data;
    data = (char *)malloc(50 * sizeof(char));
    if (data == NULL) return; // Check for null to avoid dereference
    /* Initialize data as a buffer that fits the destination buffer */
    memset(data, 'A', 50 - 1); // fill with 'A's
    data[50 - 1] = '\0'; // null terminate

    char dest[50] = "";
    /* SAFE: The destination buffer is large enough to hold the data */
    strncpy(dest, data, strlen(data));
    dest[50 - 1] = '\0'; // Ensure the destination buffer is null terminated
    printf("%s\n", dest);
    free(data);
}


// [LLM PASS]
// BAD - 122
void example_2_bad(void) {
    wchar_t *data;
    data = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (data == NULL) return; // Check for null to avoid dereference
    /* FLAW: Initialize data to a large buffer */
    wmemset(data, L'B', 100 - 1); // fill with 'B's
    data[100 - 1] = L'\0'; // null terminate

    wchar_t dest[50] = L"";
    /* POTENTIAL FLAW: Possible buffer overflow if data is larger than dest */
    wcsncpy(dest, data, wcslen(data));
    dest[50 - 1] = L'\0'; // Ensure the destination buffer is null terminated
    wprintf(L"%ls\n", dest);
    free(data);
}

// GOOD - 122
void example_2_good(void) {
    wchar_t *data;
    data = (wchar_t *)malloc(50 * sizeof(wchar_t));
    if (data == NULL) return; // Check for null to avoid dereference
    /* Initialize data to fit within the destination buffer */
    wmemset(data, L'B', 50 - 1); // fill with 'B's
    data[50 - 1] = L'\0'; // null terminate

    wchar_t dest[50] = L"";
    /* SAFE: The destination buffer is large enough to hold the data */
    wcsncpy(dest, data, wcslen(data));
    dest[50 - 1] = L'\0'; // Ensure the destination buffer is null terminated
    wprintf(L"%ls\n", dest);
    free(data);
}

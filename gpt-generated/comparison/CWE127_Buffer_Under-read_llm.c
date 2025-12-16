#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


// [LLM PASS]
// BAD - 127
void example_1_bad(void) {
    wchar_t * data;
    data = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    wmemset(data, L'A', 100 - 1); /* fill with 'A's */
    data[100 - 1] = L'\0'; /* null terminate */
    
    // Flaw: Moving data pointer backwards
    data = data - 8;

    wchar_t dest[150];
    wmemset(dest, L'C', 149); /* fill with 'C's */
    dest[149] = L'\0'; /* null terminate */
    wcscpy(dest, data); // Potential under-read
    wprintf(L"%ls\n", dest);

    // Memory allocated might not be safely freed
}

// GOOD - 127
void example_1_good(void) {
    wchar_t * data;
    data = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    wmemset(data, L'A', 100 - 1); /* fill with 'A's */
    data[100 - 1] = L'\0'; /* null terminate */

    wchar_t dest[150];
    wmemset(dest, L'C', 149); /* fill with 'C's */
    dest[149] = L'\0'; /* null terminate */
    wcscpy(dest, data); // Safe copy
    wprintf(L"%ls\n", dest);

    free(data);
}


// [LLM PASS]
// BAD - 127
void example_2_bad(void) {
    char * data;
    data = (char *)malloc(50 * sizeof(char));
    if (data == NULL) {exit(-1);}
    memset(data, 'B', 50 - 1); /* fill with 'B's */
    data[50 - 1] = '\0'; /* null terminate */

    // Flaw: Setting the pointer to an address before the allocated memory
    data = data - 5;

    char dest[100];
    memset(dest, 'D', 99); /* fill with 'D's */
    dest[99] = '\0'; /* null terminate */
    strcpy(dest, data); // Potential under-read
    printf("%s\n", dest);

    // Potential memory leak
}

// GOOD - 127
void example_2_good(void) {
    char * data;
    data = (char *)malloc(50 * sizeof(char));
    if (data == NULL) {exit(-1);}
    memset(data, 'B', 50 - 1); /* fill with 'B's */
    data[50 - 1] = '\0'; /* null terminate */

    char dest[100];
    memset(dest, 'D', 99); /* fill with 'D's */
    dest[99] = '\0'; /* null terminate */
    strcpy(dest, data); // Safe copy
    printf("%s\n", dest);

    free(data);
}

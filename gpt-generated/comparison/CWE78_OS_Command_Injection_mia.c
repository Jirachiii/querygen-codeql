#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// [MIA PASS] Perplexity: 1.35
// BAD - 78
void example_1_bad(void)
{
    char command[256];
    char userInput[128];
    printf("Enter the command: ");
    fgets(userInput, sizeof(userInput), stdin);
    userInput[strcspn(userInput, "\n")] = '\0'; // Remove newline
    /* POTENTIAL FLAW: Concatenating user input directly into the command */
    snprintf(command, sizeof(command), "ls %s", userInput);
    system(command);
}

// BAD - 78
void example_2_bad(void)
{
    char buf[128];
    printf("Enter file to delete: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0'; // Remove newline
    /* POTENTIAL FLAW: Using user input in a command execution without validation */
    char command[160];
    sprintf(command, "rm %s", buf);
    system(command);
}


// [MIA PASS] Perplexity: 1.44
// GOOD - 78
void example_1_good(void)
{
    char buf[128];
    char *fileList[] = {"file1.txt", "file2.txt", "file3.txt"};
    printf("Enter the index of the file to delete (0, 1, 2): ");
    fgets(buf, sizeof(buf), stdin);
    int index = atoi(buf);
    if(index >= 0 && index < 3)
    {
        /* FIX: Validate user input using a whitelist of valid inputs */
        printf("Deleting file: %s\n", fileList[index]);
        remove(fileList[index]); // Safer file deletion method
    }
    else
    {
        printf("Invalid index.\n");
    }
}

// GOOD - 78
void example_2_good(void)
{
    char input[128];
    printf("Enter a non-sensitive argument: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0'; // Remove newline
    if (strpbrk(input, "&;`'\"|*?~<>^()[]{}$\\") == NULL) {
        /* FIX: Neutralize potential special characters before using input */
        char command[256];
        snprintf(command, sizeof(command), "echo %s", input);
        system(command);
    } else {
        printf("Invalid input detected.\n");
    }
}

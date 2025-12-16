#include <stdio.h>
#include <stdarg.h>
#include <string.h>


// [LLM PASS]
// BAD - 134
void example_1_bad(const char* userInput)
{
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "User input: %s", userInput);
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(buffer);
}

// GOOD - 134
void example_1_good(const char* userInput)
{
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "User input: %s", userInput);
    /* FIX: Specify the format, preventing a format string vulnerability */
    printf("%s", buffer);
}


// [LLM PASS]
// BAD - 134
void example_2_bad(const char* formatString)
{
    char buffer[256];
    va_list args;
    va_start(args, formatString);
    snprintf(buffer, sizeof(buffer), "Debug: ");
    /* POTENTIAL FLAW: Passing user-controlled format string */
    vsnprintf(buffer + 7, sizeof(buffer) - 7, formatString, args);
    va_end(args);
    printf(buffer);
}

// GOOD - 134
void example_2_good(const char* fixedFormat, ...)
{
    char buffer[256];
    va_list args;
    va_start(args, fixedFormat);
    /* FIX: Using a fixed format specification */
    vsnprintf(buffer, sizeof(buffer), fixedFormat, args);
    va_end(args);
    printf("%s", buffer);
}

int main() {
    // Example user input, which could be dangerous if not handled properly
    const char* dangerousInput = "This is a %s example\n";

    // Call the bad examples
    example_1_bad(dangerousInput);
    example_2_bad(dangerousInput);

    // Call the good examples
    example_1_good(dangerousInput);
    example_2_good("This is a safe example: %s\n", "Hello World");

    return 0;
}

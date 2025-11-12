import openai
import re

# Number of function to generate per CWE
num_functions = 10
# Number of vulnerable function
num_vulnerable = int(num_functions/2)
# Number of safe function
num_safe = num_functions - num_vulnerable

llm = openai.OpenAI()
model = 'gpt-4o'

cwe_data = [
    {'cwe_number': 197,
     'cwe_name': 'Numeric Truncation',
     'cwe_desc': 'Losing data when converting large values to smaller types',
     'example': '''void CWE197_Numeric_Truncation_Error_bad()
{
    int data;
    /* Initialize data */
    data = -1;
    if(staticFive==5)
    {
        {
            char inputBuffer[CHAR_ARRAY_SIZE] = "";
            /* POTENTIAL FLAW: Read data from the console using fgets() */
            if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
            {
                /* Convert to int */
                data = atoi(inputBuffer);
            }
            else
            {
                printLine("fgets() failed.");
            }
        }
    }
    {
        /* POTENTIAL FLAW: Convert data to a short, possibly causing a truncation error */
        short shortData = (short)data;
        printShortLine(shortData);
    }
}'''},
    {'cwe_number': 242,
     'cwe_name': 'Use of Inherently Dangerous Function',
     'cwe_desc': 'Some functions contain vulnerabilities and should not be used',
     'example': '''void CWE242_Use_of_Inherently_Dangerous_Function_bad()
{
    if(staticTrue)
    {
        {
            char dest[DEST_SIZE];
            char *result;
            /* FLAW: gets is inherently dangerous and cannot be used safely. */
            /* INCIDENTAL CWE120 Buffer Overflow since gets is inherently dangerous and is
             * an unbounded copy. */
            result = gets(dest);
            /* Verify return value */
            if (result == NULL)
            {
                /* error condition */
                printLine("Error Condition: alter control flow to indicate action taken");
                exit(1);
            }
            dest[DEST_SIZE-1] = '\0';
            printLine(dest);
        }
    }
}'''},
    {'cwe_number': 252,
     'cwe_name': 'Unchecked Return Value',
     'cwe_desc': 'Function return values that can indicate errors are not checked',
     'example': '''void CWE252_Unchecked_Return_Value_bad()
{
    if(GLOBAL_CONST_FIVE==5)
    {
        {
            /* By initializing dataBuffer, we ensure this will not be the
             * CWE 690 (Unchecked Return Value To NULL Pointer) flaw for fgets() and other variants */
            char dataBuffer[100] = "";
            char * data = dataBuffer;
            printLine("Please enter a string: ");
            /* FLAW: Do not check the return value */
            fgets(data, 100, stdin);
            printLine(data);
        }
    }
}
'''},
    {'cwe_number': 253,
     'cwe_name': 'Incorrect Check of Function Return Value',
     'cwe_desc': 'Function return values that can indicate errors are checked, but incorrectly',
     'example': '''void CWE253_Incorrect_Check_of_Function_Return_Value_bad()
{
    while(1)
    {
        /* FLAW: fprintf() might fail, in which case the return value will be negative, but
         * we are checking to see if the return value is 0 */
        if (fprintf(stdout, "%s\n", "string") == 0)
        {
            printLine("fprintf failed!");
        }
        break;
    }
}
'''},
    {'cwe_number': 364,
     'cwe_name': 'Signal Handler Race Condition',
     'cwe_desc': 'Signal handlers can interrupt normal program execution at any time. If both the signal handler and main code access the same variable, a race condition can occur. Non-atomic operations can be interrupted mid-sequence',
     'example': '''structSigAtomic *CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad = NULL;
static void helperBad(int sig)
{
    if (CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad != NULL)
    {
        CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad->val = 2;
    }
}
void CWE364_Signal_Handler_Race_Condition_bad()
{
    {
        structSigAtomic *gStructSigAtomic = NULL;
        signal(SIGINT, SIG_DFL);
        if (CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad != NULL)
        {
            free(CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad);
            CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad = NULL;
        }
        gStructSigAtomic = (structSigAtomic*)malloc(sizeof(structSigAtomic));
        if (gStructSigAtomic == NULL) {exit(-1);}
        CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad = gStructSigAtomic;
        CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad->val = 1;
        /* Assign CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad BEFORE
         * calling 'signal', because pointer types are not (according to spec), atomic
         * with respect to signals.
         *
         * In practice they are on most (all?) POSIX-y computers, but thems the
         * rules
         */
        signal(SIGINT, helperBad);
        /* FLAW: This test, free, and set operation is not atomic, so if signal
         * delivery occurs (for example) between the free and setting to NULL,
         * the signal handler could corrupt the heap, cause an access violation,
         * etc
         *
         * Technically, "CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad = 0" is not atomic on certain theoretical computer
         * systems that don't actually exist, but this should trigger on
         * theoretical as well as actual computer systems.
         */
        if (CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad != NULL)
        {
            free(CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad);
            CWE364_Signal_Handler_Race_Condition__basic_01StructSigAtomicBad = NULL;
        }
    }
}
'''},
]

for cwe in cwe_data:
    cwe_number = cwe['cwe_number']
    cwe_name = cwe['cwe_name']
    cwe_description = cwe['cwe_desc']
    example_function = cwe['example']

    PROMPT_TEMPLATE = f"""You are a C programming expert tasked with generating diverse test cases for static analysis tools.

    **CWE Information:**
    - **CWE-{cwe_number}**: {cwe_name}
    - **Description**: {cwe_description}

    **Example from Reference Dataset:**
    ```c
    {example_function}
    ```

    **Your Task:**
    Generate {num_functions} C functions ({num_vulnerable} vulnerable + {num_safe} safe) that test detection of {cwe_name}.

    **Requirements:**

    1. **Vulnerable Functions ({num_vulnerable} functions):**
    - Each should contain the CWE-{cwe_number} weakness
    - Vary the context: file I/O, network operations, user input processing, data structures, etc.
    - Use realistic variable names and scenarios
    - Each function should be self-contained and compilable

    2. **Safe Functions ({num_safe} functions):**
    - Implement similar functionality WITHOUT the vulnerability
    - Show correct/secure alternatives
    - Use the same contexts as vulnerable versions
    - Should be realistic code that might appear in production

    **Format Requirements:**
    - Start each function with a comment: `// BAD - CWE-{cwe_number}: <brief reason>` or `// GOOD - <what makes it safe>`
    - Make functions compilable (include necessary types, constants)
    - Use standard C library functions
    - Keep functions focused (20-50 lines each)
    - Add inline comments explaining key points

    **Diversity Guidelines:**
    - Use different function names and contexts
    - Vary buffer sizes, data types, and control structures
    - Include different triggering conditions
    - Mix stack and heap allocations (where relevant)
    - Use different input sources (stdin, files, network, arguments)

    **Output Format:**
    ```c
    // BAD - CWE-{cwe_number}: <specific reason why it's vulnerable>
    void vulnerable_example_1(void) {{
        // implementation
    }}

    // GOOD - <what makes this safe>
    void safe_example_1(void) {{
        // implementation
    }}

    // ... (continue for all {num_functions} functions)
    ```

    Generate the functions now:"""

    response = llm.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": PROMPT_TEMPLATE}
            ]
        )
    
    response_str = response.choices[0].message.content

    pattern = r'```(?:\w+)?\n(.*?)\n```'
    match = re.search(pattern, response_str, re.DOTALL)
    if match:
        result = match.group(1).strip()
        with open(f'output/CWE{cwe_number}_gpt_generated.c', 'w') as f:
            f.write(result)
    else:
        print("GPT did not generate function")
        print(response_str)

    

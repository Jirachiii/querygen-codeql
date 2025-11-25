#!/usr/bin/env python3
"""
Call GPT to generate example good/bad testcases for a CWE, then call again to evaluate the validity of
those examples. The ones that pass the evaluation stage is all saved into a file.
"""

import openai
import re
import glob
import os

# Number of function to generate per CWE
num_functions = 4
# Number of vulnerable function
num_vulnerable = int(num_functions/2)
# Number of safe function
num_safe = num_functions - num_vulnerable

llm = openai.OpenAI()
model = 'gpt-4o'

cwe_data = [
    {'cwe_number': 15,
     'cwe_name': 'External Control of Sydtem or Configuration Setting',
     'cwe_desc': 'One or more system settings or configuration elements can be externally controlled by a user',
     'folder': 'CWEs/CWE15_External_Control_of_System_or_Configuration_Setting/'
    },
    {'cwe_number': 23,
     'cwe_name': 'Relative Path Traversal',
     'cwe_desc': 'The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory',
     'folder': 'CWEs/CWE23_Relative_Path_Traversal/'
    },
    {'cwe_number': 36,
     'cwe_name': 'Absolute Path Traversals',
     'cwe_desc': 'The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as "/abs/path" that can resolve to a location that is outside of that directory',
     'folder': 'CWEs/CWE36_Absolute_Path_Traversal/'
    },   
    {'cwe_number': 78,
     'cwe_name': 'OS Command Injection',
     'cwe_desc': 'The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component',
     'folder': 'CWEs/CWE78_OS_Command_Injection/'
    },
    {'cwe_number': 90,
     'cwe_name': 'LDAP Injection',
     'cwe_desc': 'The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component',
     'folder': 'CWEs/CWE90_LDAP_Injection/'
    },     
    {'cwe_number': 114,
     'cwe_name': 'Process Control',
     'cwe_desc': 'Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker',
     'folder': 'CWEs/CWE114_Process_Control/'
    },   
    {'cwe_number': 197,
     'cwe_name': 'Numeric Truncation',
     'cwe_desc': 'Truncation errors occur when a primitive is cast to a primitive of a smaller size and data is lost in the conversion',
     'folder': 'CWEs/CWE197_Numeric_Truncation_Error/'
    },
    {'cwe_number': 242,
     'cwe_name': 'Use of Inherently Dangerous Function',
     'cwe_desc': 'The product calls a function that can never be guaranteed to work safely',
     'folder': 'CWEs/CWE242_Use_of_Inherently_Dangerous_Function/'
    },
    {'cwe_number': 252,
     'cwe_name': 'Unchecked Return Value',
     'cwe_desc': 'The product does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions',
     'folder': 'CWEs/CWE252_Unchecked_Return_Value/'
    },
    {'cwe_number': 253,
     'cwe_name': 'Incorrect Check of Function Return Value',
     'cwe_desc': 'The product incorrectly checks a return value from a function, which prevents it from detecting errors or exceptional conditions',
     'folder': 'CWEs/CWE253_Incorrect_Check_of_Function_Return_Value/'
    },
    {'cwe_number': 364,
     'cwe_name': 'Signal Handler Race Condition',
     'cwe_desc': 'The product uses a signal handler that introduces a race condition',
     'folder': 'CWEs/CWE364_Signal_Handler_Race_Condition/'
    }
]

for cwe in cwe_data:
    # Get CWE information
    cwe_number = cwe['cwe_number']
    cwe_name = cwe['cwe_name']
    cwe_description = cwe['cwe_desc']

    # Get an example function
    cwe_folder = cwe['folder']
    c_files = glob.glob(os.path.join(cwe_folder, f"**/*.c*"), recursive=True) 
    if not c_files:
        print(f"Error: No C/Cpp files found in {cwe_folder}")
        continue

    # Grab a C file, any C file, to extract example function
    example_function = ""

    for c_file_path in c_files:
        with open(c_file_path, 'r', encoding='utf-8') as f:
            c_file_content = f.read()

        bad_pattern = r'#ifndef OMITBAD\n(.*?)#endif /\* OMITBAD \*/'
        bad_match = re.search(bad_pattern, c_file_content, re.DOTALL)
        if bad_match:
            example_function = bad_match.group(1)
            break

    if example_function == "":
        print(f"Error: Found no example funtion in folder {cwe_folder}")

    # Generation prompt
    GENERATE_PROMPT_TEMPLATE = f"""You are a C programming expert tasked with generating diverse test cases for static analysis tools.

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
    // BAD - {cwe_number}
    void example_1_bad(void) {{
        // implementation
    }}

    // GOOD - {cwe_number}
    void example_1_good(void) {{
        // implementation
    }}

    // ... (continue for all {num_functions} functions)
    ```

    Generate the functions now:"""

    response = llm.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": GENERATE_PROMPT_TEMPLATE}
            ]
        )
    
    response_str = response.choices[0].message.content
    pattern = r'```(?:\w+)?\n(.*?)\n```'
    match = re.search(pattern, response_str, re.DOTALL)

    if not match:
        print("GPT did not generate function")
        print(response_str)
        continue
    else:
        response_content = match.group(1).strip()
        response_content = response_content.split('\n')
    
    # Separate the CWE functions
    # This is hard code
    header = ""
    generated_functions = []
    header_flag = 1 # Reading header
    function_reading = ""   # Function being read
    for line in response_content:
        # If found beginning of function(a comment indicating good/bad characteristics)
        if line.startswith("// BAD") or line.startswith("// GOOD"):
            # No longer reading header
            header_flag = 0
            # Add the current function(if exist) to list
            if function_reading:
                generated_functions.append(function_reading)
                function_reading = ""

        # If reading header, add line to header
        if header_flag:
            header += line + '\n'
            continue
        
        function_reading += line + '\n'
    # Add the last function
    generated_functions.append(function_reading)
    assert len(generated_functions)%2 == 0, f"The number of good and bad functions for CWE-{cwe_number} is uneven: {len(generated_functions)}"

    # Add header to evaluated file
    validated_file = f"gpt-generated/examples/CWE{cwe_number}_{cwe_name.replace(' ', '_')}_validated.c"
    with open(validated_file, 'w') as f:
        f.write(header)

    for i in range(0, len(generated_functions), 2):
        bad_example = header + generated_functions[i]
        good_example = generated_functions[i+1]
        PROMPT_TEMPLATE = f"""You are a C programming expert tasked with evaluating the validity of test case pairs for static analysis tools.

**CWE Information:**
- **CWE-{cwe_number}**: {cwe_name}
- **Description**: {cwe_description}

**Test Case Pair for CWE-{cwe_number}:**
The pair consists of two functions, labeled 'BAD' (intended to be vulnerable) and 'GOOD' (intended to be safe).

```c
{bad_example}
{good_example}
```

**Your Task:** Evaluate the quality of this pair based on the following criteria:
- Vulnerable Function Validity (BAD): Does the BAD function unambiguously and directly demonstrate the CWE-{cwe_number} weakness?
- Safe Function Validity (GOOD): Does the GOOD function completely and securely eliminate the weakness found in the BAD function, typically by applying the correct, secure fix?
- Context Alignment: Do both functions implement similar core functionality using the same general context (e.g., file handling, network input, etc.), ensuring the GOOD function serves as a direct, secure alternative to the BAD function?
If and only if all three criteria are met, return Yes. Otherwise, return No.

Answer with Yes or No:"""

        response = llm.chat.completions.create(
                model=model,
                messages=[
                    {"role": "user", "content": PROMPT_TEMPLATE}
                ]
            )
        
        response_str = response.choices[0].message.content

        if response_str.lower().startswith("yes"):
            print(f"One pair of CWE-{cwe_number} examples accepted")
            with open(validated_file, 'a') as f:
                f.write(generated_functions[i] + good_example)
        elif response_str.lower().startswith("no"):
            print(f"One pair of CWE-{cwe_number} examples rejected")
        else:
            print("GPT did not generate answer in the right format")
            print(response_str)

    

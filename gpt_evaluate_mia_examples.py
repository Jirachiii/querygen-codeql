#!/usr/bin/env python3
"""
Generate C test cases for CWEs.
Performs Dual Validation:
1. MIA (Membership Inference Attack): valid if logprob > threshold.
2. LLM (Self-Refinement): valid if LLM answers "Yes" to quality check.
Saves results to separate files for comparison.
"""

import openai
import re
import glob
import os
import numpy as np

# --- Configuration ---
num_functions = 4  # Total functions to generate per prompt
num_vulnerable = int(num_functions/2)
num_safe = num_functions - num_vulnerable

# MIA Threshold: Perplexity
# Lower values indicate higher confidence/memorization.
# 1.0 is perfect confidence. 
# Values < 2.0 are generally considered very high confidence for code.
PERPLEXITY_THRESHOLD = 2.0

client = openai.OpenAI()
model = 'gpt-4o'

# Add your CWEs here
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
    {'cwe_number': 121,
     'cwe_name': 'Stack-based Buffer Overflow',
     'cwe_desc': 'The software writes more data to a buffer located on the stack than what is actually allocated for that buffer, which can corrupt data, crash the program, or lead to the execution of malicious code',
     'folder': 'CWEs/CWE121_Stack_Based_Buffer_Overflow/'
    },
    {'cwe_number': 122,
     'cwe_name': 'Heap-based Buffer Overflow',
     'cwe_desc': 'The software writes more data to a buffer located on the heap than what is actually allocated for that buffer, which can corrupt data, crash the program, or lead to the execution of malicious code',
     'folder': 'CWEs/CWE122_Heap_Based_Buffer_Overflow/' 
    },
    {
        'cwe_number': 124,
        'cwe_name': 'Buffer Underwrite',
        'cwe_desc': 'The software writes data before the beginning of a buffer, which can corrupt data, crash the program, or lead to the execution of malicious code',
        'folder': 'CWEs/CWE124_Buffer_Underwrite/'
    },
    {
        'cwe_number': 126,
        'cwe_name': 'Buffer Over-read',
        'cwe_desc': 'The software reads data past the end, or before the beginning, of a buffer, which can lead to information disclosure, application crashes, or other erratic behavior',
        'folder': 'CWEs/CWE126_Buffer_Overread/'
    },
    {
        'cwe_number': 127,
        'cwe_name': 'Buffer Under-read',
        'cwe_desc': 'The software reads data before the beginning of a buffer, which can lead to information disclosure, application crashes, or other erratic behavior',
        'folder': 'CWEs/CWE127_Buffer_Underread/'
    },
    {
        'cwe_number': 134,
        'cwe_name': 'Unontrolled Format String',
        'cwe_desc': 'The software uses a function that accepts a format string from an external source, but it does not validate or sanitize the format string before using it, which can lead to memory corruption and code execution',
        'folder': 'CWEs/CWE134_Uncontrolled_Format_String/'
    },
    {
        'cwe_number': 176,
        'cwe_name': 'Improper Handling of Unicode Encoding',
        'cwe_desc': 'The product does not properly handle Unicode encoding, which can lead to security vulnerabilities such as buffer overflows, information disclosure, and denial of service',
        'folder': 'CWEs/CWE176_Improper_Handling_of_Unicode_Encoding/'
    },
    {
        'cwe_number': 188,
        'cwe_name': 'Reliance on Data Memory Layout',
        'cwe_desc': 'The software relies on a specific memory layout for data structures, which can lead to vulnerabilities when the layout changes due to compiler optimizations or platform differences',
        'folder': 'CWEs/CWE188_Reliance_on_Data_Memory_Layout/'
    },
    {
        'cwe_number': 190,
        'cwe_name': 'Integer Overflow',
        'cwe_desc': 'The product performs an arithmetic operation that can result in an integer overflow or wraparound, which can lead to unexpected behavior, memory corruption, and security vulnerabilities',
        'folder': 'CWEs/CWE190_Integer_Overflow/'
    },
    {
        'cwe_number': 191,
        'cwe_name': 'Integer Underflow',
        'cwe_desc': 'The product performs an arithmetic operation that can result in an integer underflow, which can lead to unexpected behavior, memory corruption, and security vulnerabilities',
        'folder': 'CWEs/CWE191_Integer_Underflow/'
    },
    {
        'cwe_number': 194,
        'cwe_name': 'Unexpected Sign Extension',
        'cwe_desc': 'The product does not properly handle sign extension when converting between signed and unsigned data types, which can lead to unexpected behavior and security vulnerabilities',
        'folder': 'CWEs/CWE194_Unexpected_Sign_Extension/'
    },
    {
        'cwe_number': 195,
        'cwe_name': 'Signed to Unsigned Conversion Error',
        'cwe_desc': 'The product incorrectly converts a signed integer to an unsigned integer, which can lead to unexpected behavior and security vulnerabilities',
        'folder': 'CWEs/CWE195_Signed_to_Unsigned_Conversion_Error/'
    },
    {
        'cwe_number': 196,
        'cwe_name': 'Unsigned to Signed Conversion Error',
        'cwe_desc': 'The product incorrectly converts an unsigned integer to a signed integer, which can lead to unexpected behavior and security vulnerabilities',
        'folder': 'CWEs/CWE196_Unsigned_to_Signed_Conversion_Error/'
    }, 
    {'cwe_number': 197,
     'cwe_name': 'Numeric Truncation',
     'cwe_desc': 'Truncation errors occur when a primitive is cast to a primitive of a smaller size and data is lost in the conversion',
     'folder': 'CWEs/CWE197_Numeric_Truncation_Error/'
    },
    {
        'cwe_number': 222,
        'cwe_name': 'Truncation of Security-Relevant Information',
        'cwe_desc': 'The product truncates security-relevant information, which can lead to security vulnerabilities such as information disclosure and privilege escalation',
        'folder': 'CWEs/CWE222_Truncation_of_Security_Relevant_Information/'
    },
    {
        'cwe_number': 223,
        'cwe_name': 'Omission of Security-Relevant Information',
        'cwe_desc': 'The product omits security-relevant information, which can lead to security vulnerabilities such as information disclosure and privilege escalation',
        'folder': 'CWEs/CWE223_Omission_of_Security_Relevant_Information/'
    },
    {
        'cwe_number': 226,
        'cwe_name': 'Sensitive Information Uncleared Before Release',
        'cwe_desc': 'The product does not clear sensitive information from memory before releasing it, which can lead to information disclosure',
        'folder': 'CWEs/CWE226_Sensitive_Information_Uncleared_Before_Release/'
    },
    {
        'cwe_number': 242,
        'cwe_name': 'Use of Inherently Dangerous Function',
        'cwe_desc': 'The product calls a function that can never be guaranteed to work safely',
        'folder': 'CWEs/CWE242_Use_of_Inherently_Dangerous_Function/'
    },
    {
        'cwe_number': 242,
        'cwe_name': 'Use of Inherently Dangerous Function',
        'cwe_desc': 'The product calls a function that can never be guaranteed to work safely',
        'folder': 'CWEs/CWE242_Use_of_Inherently_Dangerous_Function/'
    },
    {
        'cwe_number': 244,
        'cwe_name': 'Heap Inspection',
        'cwe_desc': 'The product does not properly protect sensitive information stored on the heap, which can lead to information disclosure',
        'folder': 'CWEs/CWE244_Heap_Inspection/'    
    },
    {
        'cwe_number': 247,
        'cwe_name': 'Reliance on DNS Lookups in Security Decision',
        'cwe_desc': 'The product relies on DNS lookups to make security decisions, which can be manipulated by an attacker to redirect traffic or impersonate a trusted entity',
        'folder': 'CWEs/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/'
    },
    {
        'cwe_number': 252,
        'cwe_name': 'Unchecked Return Value',
        'cwe_desc': 'The product does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions',
        'folder': 'CWEs/CWE252_Unchecked_Return_Value/'
    },
    {
        'cwe_number': 253,
        'cwe_name': 'Incorrect Check of Function Return Value',
        'cwe_desc': 'The product incorrectly checks a return value from a function, which prevents it from detecting errors or exceptional conditions',
        'folder': 'CWEs/CWE253_Incorrect_Check_of_Function_Return_Value/'
    },
    {
        'cwe_number': 256,
        'cwe_name': 'Plaintext Storage of a Password',
        'cwe_desc': 'The product stores a password in plaintext, which can lead to unauthorized access if the storage location is compromised',
        'folder': 'CWEs/CWE256_Plaintext_Storage_of_a_Password/'
    },
    {
        'cwe_number': 259,
        'cwe_name': 'Hard-coded Password',
        'cwe_desc': 'The product contains a hard-coded password, which can be easily discovered and exploited by an attacker',
        'folder': 'CWEs/CWE259_Hard_Coded_Password/'    
    },
    {
        'cwe_number': 272,
        'cwe_name': 'Least Privilege Violation',
        'cwe_desc': 'The product does not adhere to the principle of least privilege, which can lead to unauthorized access and privilege escalation',
        'folder': 'CWEs/CWE272_Least_Privilege_Violation/'
    },
    {
        'cwe_number': 273,
        'cwe_name': 'Improper Check for Dropped Privileges',
        'cwe_desc': 'The product does not properly check for dropped privileges, which can lead to unauthorized access and privilege escalation',
        'folder': 'CWEs/CWE273_Improper_Check_for_Dropped_Privileges/'
    },
    {
        'cwe_number': 284,
        'cwe_name': 'Improper Access Control',
        'cwe_desc': 'The product does not properly restrict access to resources, which can lead to unauthorized access and privilege escalation',
        'folder': 'CWEs/CWE284_Improper_Access_Control/'    
    },
    {
        'cwe_number': 319,
        'cwe_name': 'Cleartext Tx Sensitive Info',
        'cwe_desc': 'The product transmits sensitive information in cleartext, which can be intercepted and read by an attacker',
        'folder': 'CWEs/CWE319_Cleartext_Tx_Sensitive_Info/'
    },
    {
        'cwe_number': 321,
        'cwe_name': 'Hard-coded Cryptographic Key',
        'cwe_desc': 'The product uses a hard-coded cryptographic key, which can be easily discovered and exploited by an attacker',
        'folder': 'CWEs/CWE321_Hard_Coded_Cryptographic_Key/'
    },
    {
        'cwe_number': 325,
        'cwe_name': 'Missing Required Cryptographic Step',
        'cwe_desc': 'The product omits a required cryptographic step, which can weaken the security of the cryptographic operation',
        'folder': 'CWEs/CWE325_Missing_Required_Cryptographic_Step/'
    },
    {
        'cwe_number': 327,
        'cwe_name': 'Use Broken Crypto',
        'cwe_desc': 'The product uses a cryptographic algorithm or protocol that is known to be broken or weak, which can lead to unauthorized access and data compromise',
        'folder': 'CWEs/CWE327_Use_Broken_Crypto/'
    },
    {
        'cwe_number': 328,
        'cwe_name': 'Reversible One Way Hash',
        'cwe_desc': 'The product uses a one-way hash function that is reversible, which can lead to unauthorized access and data compromise',
        'folder': 'CWEs/CWE328_Reversible_One_Way_Hash/'
    },
    {
        'cwe_number': 338,
        'cwe_name': 'Weak PRNG',
        'cwe_desc': 'The product uses a pseudo-random number generator (PRNG) that is weak or predictable, which can lead to unauthorized access and data compromise',
        'folder': 'CWEs/CWE338_Weak_PRNG/'
    }
]
    
def get_tokens_for_text(full_text, target_text, logprobs_list, start_search_offset=0):
    """
    Locates the target_text within full_text (starting from offset) and returns
    the list of logprobs corresponding to that text range.
    Returns: (matched_logprobs, new_offset)
    """
    # 1. Find the character range in the full text
    # We strip to avoid mismatch due to trailing newlines added/removed during parsing
    clean_target = target_text.strip()
    if not clean_target:
        return [], start_search_offset
        
    start_idx = full_text.find(clean_target, start_search_offset)
    if start_idx == -1:
        # Fallback: simpler search or just ignore (could happen if parsing changed text significantly)
        return [], start_search_offset
    
    end_idx = start_idx + len(clean_target)
    
    # 2. Map character range to tokens
    selected_logprobs = []
    current_char_pos = 0
    
    # We iterate tokens to find which ones overlap with [start_idx, end_idx]
    # This is efficient enough for small batch sizes
    for token_data in logprobs_list:
        token_str = token_data.token
        token_len = len(token_str)
        token_start = current_char_pos
        token_end = current_char_pos + token_len
        
        # If token is within the range (overlaps significantly)
        # We assume if the token starts inside the range, it belongs to it
        if token_start >= start_idx and token_start < end_idx:
            selected_logprobs.append(token_data.logprob)
        
        current_char_pos += token_len
        
        # Optimization: Stop if we passed the section
        if current_char_pos > end_idx + 100: # buffer
            break
            
    return selected_logprobs, end_idx

def validate_with_llm(bad_code, good_code, cwe_info):
    """
    Asks the LLM to evaluate the quality of the pair.
    Returns True if LLM says 'Yes'.
    """
    PROMPT_TEMPLATE = f"""You are a C programming expert.

**CWE Information:**
- **CWE-{cwe_info['cwe_number']}**: {cwe_info['cwe_name']}
- **Description**: {cwe_info['cwe_desc']}

**Test Case Pair:**
```c
{bad_code}
{good_code}
````

**Your Task:** Evaluate this pair.

1.  Does the BAD function unambiguously demonstrate CWE-{cwe_info['cwe_number']}?
2.  Does the GOOD function securely eliminate the weakness?
3.  Do both functions use similar context?

If and only if all criteria are met, return Yes. Otherwise, return No.
Answer with Yes or No:"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": PROMPT_TEMPLATE}],
            temperature=0.2 # Low temp for deterministic evaluation
        )
        ans = response.choices[0].message.content.strip().lower()
        return ans.startswith("yes")
    except Exception as e:
        print(f"    > LLM Validation Error: {e}")
        return False

# \--- Main Logic ---

output_dir = "gpt-generated/comparison"
os.makedirs(output_dir, exist_ok=True)

for cwe in cwe_data:
    cwe_number = cwe['cwe_number']
    cwe_name = cwe['cwe_name']
    cwe_description = cwe['cwe_desc']
    cwe_folder = cwe['folder']

    # 1. Find Example Function (Your existing logic)
    c_files = glob.glob(os.path.join(cwe_folder, f"**/*.c*"), recursive=True) 
    if not c_files:
        print(f"Error: No C/Cpp files found in {cwe_folder}")
        continue

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
        print(f"Error: Found no example function in {cwe_folder}")
        # continue # Optional: skip or try to generate anyway

    print(f"Generating examples for CWE-{cwe_number}...")

    GENERATE_PROMPT_TEMPLATE = f"""You are a C programming expert tasked with generating diverse test cases for static analysis tools.

    **CWE Information:**
    - **CWE-{cwe_number}**: {cwe_name}
    - **Description**: {cwe_description}

    **Example from Reference Dataset:**
    ```c
    {example_function}
    ```

    **Your Task:**
    Generate {num_functions} C functions ({num_vulnerable} vulnerable + {num_safe} safe).

    **Format Requirements:**
    - Start each function with a comment: `// BAD` or `// GOOD`.
    - Include all necessary C headers/imports at the top.

    **Output Format:**
    ```c
    #include <stdio.h>
    // ... headers

    // BAD - {cwe_number}
    void example_1_bad(void) {{ ... }}

    // GOOD - {cwe_number}
    void example_1_good(void) {{ ... }}
    ```
    Generate now:"""

    # 2. Generate with Logprobs
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": GENERATE_PROMPT_TEMPLATE}],
            logprobs=True,
            top_logprobs=1
        )
    except Exception as e:
        print(f"API Error: {e}")
        continue

    response_msg = response.choices[0].message
    full_text = response_msg.content
    logprobs_list = response.choices[0].logprobs.content

    # 3. Parse Header and Functions (Your Logic)
    pattern = r'```(?:\w+)?\n(.*?)\n```'
    match = re.search(pattern, full_text, re.DOTALL)

    if not match:
        print("GPT did not generate valid code block")
        continue

    response_content = match.group(1).strip().split('\n')

    header = ""
    generated_functions = []
    header_flag = 1 
    function_reading = "" 

    for line in response_content:
        # If found beginning of function
        if line.startswith("// BAD") or line.startswith("// GOOD"):
            header_flag = 0
            if function_reading:
                generated_functions.append(function_reading)
                function_reading = ""

        if header_flag:
            header += line + '\n'
            continue
        
        function_reading += line + '\n'

    generated_functions.append(function_reading)

    if len(generated_functions) % 2 != 0:
        print(f"Error: Uneven functions generated ({len(generated_functions)}). Skipping.")
        continue

    # 4. Prepare Output Files
    output_dir = "gpt-generated/comparison"
    os.makedirs(output_dir, exist_ok=True)

    mia_file = os.path.join(output_dir, f"CWE{cwe_number}_{cwe_name.replace(' ', '_')}_mia.c")
    llm_file = os.path.join(output_dir, f"CWE{cwe_number}_{cwe_name.replace(' ', '_')}_llm.c")

    # Initialize files with the header
    with open(mia_file, 'w') as f: f.write(header)
    with open(llm_file, 'w') as f: f.write(header)

    # 5. Evaluate Pairs
    current_search_offset = 0 # Track position in full text for efficient searching

    # Locate the header in full_text first to advance offset
    _, current_search_offset = get_tokens_for_text(full_text, header, logprobs_list, 0)

    for i in range(0, len(generated_functions), 2):
        bad_func = generated_functions[i]
        good_func = generated_functions[i+1]
        
        # --- A. MIA Validation ---
        # Get logprobs for BAD function
        bad_probs, current_search_offset = get_tokens_for_text(full_text, bad_func, logprobs_list, current_search_offset)
        # Get logprobs for GOOD function
        good_probs, current_search_offset = get_tokens_for_text(full_text, good_func, logprobs_list, current_search_offset)
        
        pair_probs = bad_probs + good_probs
        
        if pair_probs:
            avg_log_prob = np.mean(pair_probs)
            perplexity = np.exp(-1 * avg_log_prob)
        else:
            perplexity = 999.0 # Fail safe
            
        if perplexity < PERPLEXITY_THRESHOLD:
            print(f"  > Pair {i//2 + 1}: MIA PASS (Perplexity {perplexity:.2f})")
            with open(mia_file, 'a') as f:
                f.write(f"\n// [MIA PASS] Perplexity: {perplexity:.2f}\n")
                f.write(bad_func)
                f.write(good_func)
        else:
            print(f"  > Pair {i//2 + 1}: MIA FAIL (Perplexity {perplexity:.2f})")

        # --- B. LLM Validation ---
        is_valid_llm = validate_with_llm(bad_func, good_func, cwe)
        
        if is_valid_llm:
            print(f"  > Pair {i//2 + 1}: LLM PASS")
            with open(llm_file, 'a') as f:
                f.write(f"\n// [LLM PASS]\n")
                f.write(bad_func)
                f.write(good_func)
        else:
            print(f"  > Pair {i//2 + 1}: LLM FAIL")

    print(f"Done. Files saved to {output_dir}") 
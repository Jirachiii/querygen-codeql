#!/usr/bin/env python3
"""
Call GPT to generate example good/bad testcases for a CWE, then call again to evaluate the validity of
those examples. The ones that pass the evaluation stage are all saved into a file.
"""

import os
import re
import glob
import openai
import anthropic

# --- Configuration ---
# 0: Original (Generate diverse random examples)
# 1: Precision Improvement (Generate Tricky FPs for a generic pattern)
# 2: Pattern Bypass (Generate FNs that the specific pattern misses)
GENERATION_MODE = 0 

# Number of function to generate per CWE
num_functions = 4
# Number of vulnerable function
num_vulnerable = int(num_functions/2)
# Number of safe function
num_safe = num_functions - num_vulnerable

# Ensure you have your OPENAI_API_KEY environment variable set, 
# or instantiate the client with api_key="sk-..."
llm = openai.OpenAI()
model = 'gpt-4o'

anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
if not anthropic_api_key:
    raise ValueError("Please set the ANTHROPIC_API_KEY environment variable.")
anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
CLAUDE_MODEL = 'claude-sonnet-4-5-20250929'


cwe_data = [
    {'cwe_number': 121,
     'cwe_name': 'Stack-based Buffer Overflow',
     'cwe_desc': 'The software writes more data to a buffer located on the stack than what is actually allocated for that buffer.',
     'folder': 'CWEs/CWE121_Stack_Based_Buffer_Overflow/',
     'semgrep_pattern': """patterns:
      - pattern: |
          if ($INDEX >= 0) {
            $ARRAY[$INDEX] = 1;
          }
      - pattern-not: |
          if ($INDEX >= 0 && $INDEX < $ARRAY_SIZE) {
            $ARRAY[$INDEX] = 1;
          }
""" 
    }
]

def get_mode_instructions(mode, pattern, num_vuln, num_safe, cwe_num):
    """Returns the specific instructions based on the selected generation mode."""
    base_reqs = f"""
    **Format Requirements:**
    - Start each function with a comment: `// BAD - CWE-{cwe_num}: <brief reason>` or `// GOOD - <what makes it safe>`
    - Make functions compilable (include necessary types, constants)
    - Use standard C library functions
    - Keep functions focused (20-50 lines each)
    - Add inline comments explaining key points
    """
    
    if mode == 1 and pattern:
        return f"""
    **Task: Improve Pattern Precision (Reduce False Positives)**
    I have a GENERIC Semgrep pattern used to detect this CWE, but it lacks precision.
    
    **Semgrep Pattern:**
    ```yaml
    {pattern}
    ```

    **Requirements:**
    1. **Safe Functions (GOOD) ({num_safe} functions):** - CRITICAL: Generate "Tricky" code that is SAFE but *looks* like it matches the pattern above (False Positives).
       - Example: If pattern looks for strcpy, generate a safe wrapper around strcpy or a safe usage that syntactically resembles the bad pattern.
    
    2. **Vulnerable Functions (BAD) ({num_vuln} functions):**
       - Generate standard vulnerabilities that DO match the pattern to ensure we maintain recall.

    {base_reqs}
    """

    elif mode == 2 and pattern:
        return f"""
    **Task: Bypass Specific Pattern (Generate False Negatives)**
    I have a SPECIFIC Semgrep pattern, and I want to find vulnerabilities it misses.

    **Semgrep Pattern:**
    ```yaml
    {pattern}
    ```

    **Requirements:**
    1. **Vulnerable Functions (BAD) ({num_vuln} functions):**
       - CRITICAL: Implement the CWE-{cwe_num} weakness in a way that the pattern above will FAIL to detect (False Negative).
       - Use complex control flow, variable aliasing, pointer arithmetic, or inter-procedural data flow to hide the vulnerability from the pattern.

    2. **Safe Functions (GOOD) ({num_safe} functions):**
       - Implement standard safe alternatives.

    {base_reqs}
    """

    else:
        # Default / Original Mode
        return f"""
    **Requirements:**

    1. **Vulnerable Functions ({num_vuln} functions):**
    - Each should contain the CWE-{cwe_num} weakness
    - Vary the context: file I/O, network operations, user input processing, etc.

    2. **Safe Functions ({num_safe} functions):**
    - Implement similar functionality WITHOUT the vulnerability
    - Show correct/secure alternatives

    **Diversity Guidelines:**
    - Use different function names and contexts
    - Vary buffer sizes, data types, and control structures

    {base_reqs}
    """

for cwe in cwe_data:
    # Get CWE information
    cwe_number = cwe['cwe_number']
    cwe_name = cwe['cwe_name']
    cwe_description = cwe['cwe_desc']
    cwe_pattern = cwe.get('semgrep_pattern', '')

    # Skip if mode requires pattern but none provided
    if GENERATION_MODE in [1, 2] and not cwe_pattern:
        print(f"Skipping CWE-{cwe_number}: No Semgrep pattern provided for selected mode.")
        continue

    # Get an example function
    cwe_folder = cwe['folder']
    # Ensure this path exists or update logic to match your directory structure
    c_files = glob.glob(os.path.join(cwe_folder, f"**/*.c*"), recursive=True) 
    
    example_function = ""
    if c_files:
        for c_file_path in c_files:
            try:
                with open(c_file_path, 'r', encoding='utf-8') as f:
                    c_file_content = f.read()
                # Heuristic to find example code in Juliet test cases
                bad_pattern = r'#ifndef OMITBAD\n(.*?)#endif /\* OMITBAD \*/'
                bad_match = re.search(bad_pattern, c_file_content, re.DOTALL)
                if bad_match:
                    example_function = bad_match.group(1)
                    break
            except Exception as e:
                continue

    if example_function == "":
        print(f"Warning: Found no example function in folder {cwe_folder}. Using Description only.")

    # Get the instructions based on mode
    task_instructions = get_mode_instructions(GENERATION_MODE, cwe_pattern, num_vulnerable, num_safe, cwe_number)

    # Generation prompt
    GENERATE_PROMPT_TEMPLATE = f"""You are a C programming expert tasked with generating diverse test cases for static analysis tools.

    **CWE Information:**
    - **CWE-{cwe_number}**: {cwe_name}
    - **Description**: {cwe_description}

    **Example from Reference Dataset:**
    ```c
    {example_function}
    ```

    {task_instructions}

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
    ```

    Generate the functions now:"""

    try:
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
            print(f"GPT did not generate function for CWE-{cwe_number}")
            print(response_str)
            continue
        else:
            response_content = match.group(1).strip()
            response_content = response_content.split('\n')
        
        # Separate the CWE functions
        header = ""
        generated_functions = []
        header_flag = 1 
        function_reading = ""   
        for line in response_content:
            if line.strip().startswith("// BAD") or line.strip().startswith("// GOOD"):
                header_flag = 0
                if function_reading.strip():
                    generated_functions.append(function_reading)
                    function_reading = ""

            if header_flag:
                header += line + '\n'
                continue
            
            function_reading += line + '\n'
        
        if function_reading.strip():
            generated_functions.append(function_reading)
        
        if len(generated_functions) % 2 != 0:
            print(f"Error: Uneven number of functions generated for CWE-{cwe_number}. Skipping.")
            continue

        # Add header to validated file
        validated_file = f"gpt-generated/examples/CWE{cwe_number}_{cwe_name.replace(' ', '_')}_test.c"
        os.makedirs(os.path.dirname(validated_file), exist_ok=True)
        
        # We write header once, then append validated pairs
        with open(validated_file, 'w') as f:
            f.write(header)

        for i in range(0, len(generated_functions), 2):
            bad_example = header + generated_functions[i]
            good_example = generated_functions[i+1]
            
            # Validation Logic
            EVAL_PROMPT_TEMPLATE = f"""You are a C programming expert tasked with evaluating the validity of test case pairs for static analysis tools.

**CWE Information:**
- **CWE-{cwe_number}**: {cwe_name}
- **Description**: {cwe_description}

**Test Case Pair for CWE-{cwe_number}:**
The pair consists of two functions, labeled 'BAD' (intended to be vulnerable) and 'GOOD' (intended to be safe).

```c
{bad_example}
{good_example}
```

Your Task: Evaluate the quality of this pair based on the following criteria:
- Vulnerable Function Validity (BAD): Does the BAD function unambiguously contain the CWE-{cwe_number} weakness?
- Safe Function Validity (GOOD): Does the GOOD function securely eliminate the weakness?
- Context Alignment: Do both functions implement similar core functionality?

If and only if all three criteria are met, return Yes. Otherwise, return No.
Answer with Yes or No:"""
            print(f"  Validating Pair {int(i/2)+1} with {CLAUDE_MODEL}...")
            print(bad_example)
            print(good_example)

            claude_response = anthropic_client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=1024,
                messages=[
                {"role": "user", "content": EVAL_PROMPT_TEMPLATE}
                ]
            )

            eval_result = claude_response.content[0].text.strip()

            if eval_result.lower().startswith("yes"):
                print(f"    -> Accepted.")
                with open(validated_file, 'a') as f:
                    f.write(generated_functions[i] + "\n" + good_example + "\n")
            else:
                print(f"    -> Rejected. Reason: {eval_result}")
                
    except Exception as e:
        print(f"An unexpected error occurred processing CWE-{cwe_number}: {e}")
import openai
import os
import re
import glob
from typing import Optional, Dict

# --- Configuration ---
# Set up OpenAI client (make sure your API key is set in environment variables)
try:
    # Use gemini-2.5-flash-preview-09-2025 for the rule generation task
    llm = openai.OpenAI()
except Exception as e:
    print(f"Error initializing OpenAI client: {e}")
    print("Please ensure the OPENAI_API_KEY environment variable is set.")
    exit(1)

MODEL = 'gpt-5.1'

# Define path and extension constants for the new structure
INPUT_DIR = "CWEs-examples"
OUTPUT_DIR = "CWEs-examples/evolved"
RULE_EXTENSION = ".yaml"
DIFF_EXTENSION = ".txt"
BAD_SUFFIX = "_bad.c"
GOOD_SUFFIX = "_good.c"
EVOLVED_SUFFIX = "_evolved.yaml"

# --- Helper Function: File Reading ---

def read_file_content(path: str) -> Optional[str]:
    """Safely reads the content of a file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {path}.")
        return None
    except Exception as e:
        print(f"Error reading file {path}: {e}")
        return None

# --- Main Logic: Rule Evolution ---

def evolve_semgrep_rule(cwe_number: str, query_filename: str, current_rule: str, bad_code: str, good_code: str, diff_content: str) -> Optional[str]:
    """
    Prompts the LLM to update the Semgrep rule based on a new example and diff.
    """
    print("--- Constructing LLM Prompt ---")
    
    EVOLUTION_PROMPT_TEMPLATE = f"""
You are an expert in static analysis and Semgrep rule authoring. Your task is to improve an existing Semgrep rule for vulnerability detection by incorporating a new test case.

**VULNERABILITY TYPE:** {cwe_number} (External Control of System/Configuration Setting)

**CURRENT SEMGREP RULE (Needs Improvement):**
```yaml
{current_rule}
```

**NEW TEST CASE (Must be handled by the updated rule):**
- **VULNERABLE CODE (Must Detect):**
```c
{bad_code}
```
- **SAFE CODE (Must NOT Detect):**
```c
{good_code}
```

**GUMTREE DIFF (Vulnerable → Safe):**
This shows the minimum change to go from vulnerable (deleted lines) to safe (inserted lines).
```
{diff_content}
```

**Goal for Updated Rule:**
Generate a single, complete, valid Semgrep YAML block (`rules: [...]`) that detects the vulnerability in the VULNERABLE CODE but correctly ignores the SAFE CODE. The new rule should be more general than the current one if necessary.

**Requirements & Constraints:**
1. **Focus on Patterns:** The new rule (or rules) must focus on the core difference between the bad and good code, as indicated by the diff.
2. **Rule Structure:** You can choose to:
    a) **EDIT** the `patterns` block of the existing rule's ID (`{query_filename}_initial_v1`) to make it more effective.
    b) **ADD** a new rule to the YAML block if the new vulnerability variant is fundamentally different.
3. **Allowed Patterns ONLY:** Use ONLY these pattern types: `pattern`, `pattern-either`, `patterns`, `pattern-not`.
4. **NO Complex Features:** Do not use `metavariable-comparison`, `pattern-not-inside`, `taint` mode, or other advanced features.
5. **Output Format:** The output MUST be a single, valid YAML code block (````yaml\n...\n````).
6. **Languages:** Set `languages: [c, cpp]` if the rule is language-agnostic, or `languages: [c]` if specific.

Generate the UPDATED and COMPLETE YAML now:
"""

    print("--- Calling LLM to Evolve Rule ---")
    try:
        response = llm.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "user", "content": EVOLUTION_PROMPT_TEMPLATE}
            ]
        )
        response_str = response.choices[0].message.content
        
        # Extract YAML code block from response
        yaml_match = re.search(r'```yaml\n(.*?)\n```', response_str, re.DOTALL)
        
        if yaml_match:
            updated_yaml = yaml_match.group(1).strip()
            print("Successfully received updated YAML from LLM.")
            return updated_yaml
        else:
            print("WARNING: Could not find valid YAML code block in LLM response.")
            return None

    except Exception as e:
        print(f"An error occurred during rule evolution: {e}")
        return None

# --- Execution ---

if __name__ == '__main__':
    # 3. Find all YAML rule files in the input directory
    rule_files_to_process = glob.glob(os.path.join(INPUT_DIR, f"*{RULE_EXTENSION}"))

    if not rule_files_to_process:
        print(f"No YAML rule files found in '{INPUT_DIR}'. Exiting.")
    else:
        print(f"Found {len(rule_files_to_process)} rule file(s) to process.")
        
        for rule_path in rule_files_to_process:
            # 4. Derive corresponding file paths
            # rule_path example: 'rule_evolution_inputs/CWE15_example_01.yaml'
            
            # Get the base filename without extension: 'rule_evolution_inputs/CWE15_example_01'
            base_path_no_ext = rule_path.rsplit(RULE_EXTENSION, 1)[0]
            
            # Construct related paths
            diff_path = base_path_no_ext + DIFF_EXTENSION
            bad_code_path = base_path_no_ext + BAD_SUFFIX
            good_code_path = base_path_no_ext + GOOD_SUFFIX
            output_path = os.path.join(OUTPUT_DIR, base_path_no_ext.split('/')[-1] + EVOLVED_SUFFIX)

            print(f"\n--- Processing Rule: {os.path.basename(rule_path)} ---")

            # 5. Read all necessary file contents
            current_rule_content = read_file_content(rule_path)
            diff_content = read_file_content(diff_path)
            bad_code = read_file_content(bad_code_path)
            good_code = read_file_content(good_code_path)

            if not all([current_rule_content, diff_content, bad_code, good_code]):
                print("Skipping: One or more corresponding input files (diff, bad.c, good.c) are missing or failed to read.")
                continue

            # The query_filename for the prompt is just the base name
            query_filename = os.path.basename(base_path_no_ext)
            
            # **[CHANGE] Extract CWE number dynamically from the base filename**
            cwe_number_dynamic = query_filename.split('_')[0]
            
            # 6. Evolve the rule
            updated_rule_yaml = evolve_semgrep_rule(
                cwe_number=cwe_number_dynamic, 
                query_filename=query_filename, 
                current_rule=current_rule_content, 
                bad_code=bad_code, 
                good_code=good_code, 
                diff_content=diff_content
            )

            # 7. Save the new rule
            if updated_rule_yaml:
                try:
                    os.makedirs(OUTPUT_DIR, exist_ok=True)
                    with open(output_path, 'w') as f:
                        f.write(updated_rule_yaml)
                    print(f"\n✅ SUCCESS: Updated Semgrep rule saved to {os.path.basename(output_path)}")
                except Exception as e:
                    print(f"Error saving file: {e}")
            else:
                print(f"\n❌ FAILED: Could not generate a valid updated Semgrep rule for {query_filename}.")
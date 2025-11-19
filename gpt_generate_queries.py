import openai
import re
from pathlib import Path

input_dir = 'CWEs-examples'
output_dir = 'CWEs-examples/no-diff'

llm = openai.OpenAI()
model = 'gpt-4o'

def find_diff_files(directory):
    """
    Find all files ending with .txt in the directory.
    
    Args:
        directory: Path to the directory to search
        
    Returns:
        List of Path objects for files
    """
    dir_path = Path(directory)
    
    if not dir_path.exists():
        print(f"Error: Directory '{directory}' not found")
        return []
    
    if not dir_path.is_dir():
        print(f"Error: '{directory}' is not a directory")
        return []
    
    # Find all _bad.c and _bad.cpp files
    diff_files = []
    diff_files.extend(dir_path.glob("*.txt"))
    
    # Sort for consistent ordering
    diff_files.sort()
    
    print(f"Found {len(diff_files)} files in '{directory}'")
    return diff_files

diff_files = find_diff_files(input_dir)

for file in diff_files:
    print("Processing ", file.name)
    good_filename = str(file).replace('.txt', '_good.c')
    bad_filename = str(file).replace('.txt', '_bad.c')
    query_filename = file.name[:-4]

    cwe_number = file.name.split('_')[0]
    with open(good_filename, 'r') as f:
        good_file_content = f.read()
    with open(bad_filename, 'r') as f:
        bad_file_content = f.read()
    with open(file, 'r') as f:
        diff_content = f.read()
    PROMPT_TEMPLATE = f"""I need a Semgrep rule to detect vulnerability pattern for {cwe_number}. 

**EXAMPLE VULNERABLE CODE (Must Detect):**
{bad_file_content}

**EXAMPLE SAFE CODE (Must NOT Detect):**
{good_file_content}

**Requirements:**
Write a SIMPLE Semgrep rule that:
1. Focuses on the KEY DIFFERENCE between the two examples
2. Uses ONLY these patterns: patterns, pattern-either, pattern, pattern-not
3. NO complex features: no metavariable-comparison, no pattern-not-inside, no taint mode
4. Detects the VULNERABLE code
5. Excludes the SAFE code using pattern-not

**Strategy based on difference between examples:**
- Look at what was DELETED (vulnerable code) → this is what to detect
- Look at what was INSERTED (safe code) → this is what to exclude with pattern-not
- Keep it simple - match the core dangerous operation and exclude the safe variant

Example structure:
```yaml
rules:
  - id: {query_filename}
    message: "..."
    severity: ERROR
    metadata:
      cwe: "{cwe_number}"
    languages: [c, cpp]
    patterns:
      - pattern: [dangerous pattern from vulnerable code]
      - pattern-not: [safe pattern from safe code]
```

Format as valid YAML that can be saved directly as a .yaml file."""
    PROMPT_TEMPLATE_WITH_DIFF = f"""I need a Semgrep rule to detect vulnerability pattern for {cwe_number}. 

**EXAMPLE VULNERABLE CODE (Must Detect):**
{bad_file_content}

**EXAMPLE SAFE CODE (Must NOT Detect):**
{good_file_content}

**GUMTREE DIFF (Vulnerable → Safe):**
{diff_content}

**Requirements:**
Write a SIMPLE Semgrep rule that:
1. Focuses on the KEY DIFFERENCE shown in the diff
2. Uses ONLY these patterns: patterns, pattern-either, pattern, pattern-not
3. NO complex features: no metavariable-comparison, no pattern-not-inside, no taint mode
4. Detects the VULNERABLE code
5. Excludes the SAFE code using pattern-not

**Strategy based on diff:**
- Look at what was DELETED (vulnerable code) → this is what to detect
- Look at what was INSERTED (safe code) → this is what to exclude with pattern-not
- Keep it simple - match the core dangerous operation and exclude the safe variant

Example structure:
```yaml
rules:
  - id: {query_filename}
    message: "..."
    severity: ERROR
    metadata:
      cwe: "{cwe_number}"
    languages: [c]
    patterns:
      - pattern: [dangerous pattern from vulnerable code]
      - pattern-not: [safe pattern from safe code]
```

Format as valid YAML that can be saved directly as a .yaml file."""

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
        with open(f'{output_dir}/{query_filename}.yaml', 'w') as f:
            f.write(result)
        print(f"  ✓ Success")
    else:
        print(f"  ✗ Failed: GPT did not generate query")
        print(response_str)

    

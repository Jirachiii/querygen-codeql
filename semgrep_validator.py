#!/usr/bin/env python3
"""
Validate new examples by running them through available Semgrep rules.
"""

import os
import glob
import re
import subprocess
import json
from typing import List, Dict, Tuple, Optional

# --- Configuration ---
SOURCE_DIR = "gpt-generated/examples"
RULES_DIR = "gpt-generated/semgrep/with-diff"
C_EXTENSION = ".c*"
YAML_EXTENSION = ".yaml"

# Regex to find CWE code (e.g., CWE15) in a filename
CWE_CODE_REGEX = re.compile(r'(CWE\d+)')

# Regex to find function definitions and their names for line tracking
# It captures the function name and its starting line number.
FUNC_DEF_REGEX = re.compile(r'^\s*(?:[\w\s\*]+)\s+(\w+)\s*\([^;]*\)\s*\{', re.MULTILINE)

def get_cwe_code(filename: str) -> Optional[str]:
    """Extracts the CWE code from a filename."""
    match = CWE_CODE_REGEX.search(os.path.basename(filename))
    return match.group(0) if match else None

def find_semgrep_rules(cwe_code: str, rules_dir: str) -> List[str]:
    """Finds all YAML rule files matching the CWE code in the rules directory."""
    # Search recursively for files starting with the CWE code
    search_pattern = os.path.join(rules_dir, f"**/{cwe_code}*{YAML_EXTENSION}")
    rule_files = glob.glob(search_pattern, recursive=True)
    return rule_files

def split_file_into_pairs(filepath: str) -> Tuple[List[Dict], str]:
    """
    Splits file content into BAD/GOOD function pairs and tracks their line numbers.
    The header is everything before the first function.
    """
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.splitlines()
    pairs = []
    current_pair = {}
    header = ""
    in_header = True
    
    # Iterate through content to find function definitions and track line numbers
    for line_num, line in enumerate(lines, 1):
        if line.strip().startswith('// BAD') and 'bad' not in current_pair:
            in_header = False
            current_pair['bad'] = {'start_line': line_num + 1}
            current_pair['code_lines'] = []
            
        elif line.strip().startswith('// GOOD') and 'good' not in current_pair:
            in_header = False
            
            # Finalize the 'bad' part of the pair
            current_pair['bad']['end_line'] = line_num - 1 # End before // GOOD
            current_pair['bad']['code'] = '\n'.join(current_pair['code_lines']).strip()

            # Start the 'good' part
            current_pair['good'] = {'start_line': line_num + 1}
            current_pair['code_lines'] = [] # Reset lines for the GOOD function
            
        elif in_header:
            header += line + "\n"
            
        elif current_pair:
            current_pair['code_lines'].append(line)
            
            # Check for the end of the last function (main or EOF)
            if line_num == len(lines):
                if 'bad' in current_pair and 'good' not in current_pair:
                    current_pair['bad']['end_line'] = line_num
                    current_pair['bad']['code'] = '\n'.join(current_pair['code_lines']).strip()
                    pairs.append(current_pair)
                elif 'good' in current_pair:
                    current_pair['good']['end_line'] = line_num
                    current_pair['good']['code'] = '\n'.join(current_pair['code_lines']).strip()
                    pairs.append(current_pair)
                
            # If a new BAD or GOOD is starting, we would have already finalized the previous one.
            # Handle closing the 'good' function and starting a new pair immediately
            # We assume a function ends just before the next function starts.
            next_line_num = line_num + 1
            if next_line_num < len(lines):
                 next_line = lines[next_line_num - 1] # Line 1 is index 0
                 if next_line.strip().startswith('// BAD'):
                    if 'good' in current_pair:
                        current_pair['good']['end_line'] = line_num
                        current_pair['good']['code'] = '\n'.join(current_pair['code_lines']).strip()
                        pairs.append(current_pair)
                        current_pair = {} # Start new pair

    return [p for p in pairs if 'bad' in p and 'good' in p], header.strip()

def run_semgrep_and_analyze(c_file_path: str, rule_files: List[str], pairs: List[Dict]):
    """
    Runs Semgrep and analyzes the results for False Positives (FP) and 
    False Negatives (FN).
    """
    print(f"\n--- Running Semgrep on {os.path.basename(c_file_path)} ---")
    
    if not rule_files:
        print("No matching Semgrep rules found. Cannot run analysis.")
        return

    # Build the semgrep command
    command = ['semgrep']
    for rule in rule_files:
        command.extend(['--config', rule])
    command.extend([c_file_path, '--json'])

    try:
        # Execute Semgrep
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        
        # Check if Semgrep ran successfully (return code 0 or 1 for findings)
        if process.returncode not in [0, 1]:
            print(f"Semgrep execution failed with return code {process.returncode}.")
            print(f"Stderr:\n{process.stderr}")
            return
        
        # Parse JSON output
        semgrep_results = json.loads(process.stdout)
        findings = semgrep_results.get('results', [])
        
        # Analyze findings
        problem_pairs = []

        for i, pair in enumerate(pairs):
            pair_id = i + 1
            bad_func = pair['bad']
            good_func = pair['good']
            
            # --- FN Check: Did Semgrep miss the BAD function? ---
            bad_found = any(bad_func['start_line'] <= f['start']['line'] <= bad_func['end_line'] 
                            for f in findings if f['path'] == c_file_path)
            
            if not bad_found:
                problem_pairs.append({
                    'type': 'False Negative (FN)',
                    'message': f"Pair {pair_id}: Semgrep failed to find a vulnerability in the BAD function.",
                    'code': bad_func['code']
                })
            
            # --- FP Check: Did Semgrep incorrectly flag the GOOD function? ---
            good_found = any(good_func['start_line'] <= f['start']['line'] <= good_func['end_line'] 
                             for f in findings if f['path'] == c_file_path)
            
            if good_found:
                problem_pairs.append({
                    'type': 'False Positive (FP)',
                    'message': f"Pair {pair_id}: Semgrep incorrectly flagged the GOOD function as vulnerable.",
                    'code': good_func['code']
                })

        # --- Reporting ---
        print("\n--- Problematic Test Case Pairs ---")
        if not problem_pairs:
            print("All pairs passed the basic Semgrep validation (No FPs/FNs found).")
        else:
            for p in problem_pairs:
                print(f"\n[ISSUE: {p['type']}] - {p['message']}")

    except FileNotFoundError:
        print("\nERROR: Semgrep command not found. Please ensure Semgrep is installed and in your PATH.")
    except json.JSONDecodeError:
        print("ERROR: Failed to parse Semgrep JSON output.")
        print(f"Stdout:\n{process.stdout}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """Main execution flow for the validation pipeline."""
    search_pattern = os.path.join(SOURCE_DIR, f"**/*{C_EXTENSION}")
    c_files = glob.glob(search_pattern, recursive=True)
    c_files = ['gpt-generated/examples/CWE114_Process_Control_validated.c']
    for c_file_path in c_files:
    
        # 1. Get CWE code from the C file
        cwe_code = get_cwe_code(c_file_path)
        if not cwe_code:
            print(f"Error: Could not extract CWE code from filename: {c_file_path}")
            return
        print('Processing', cwe_code)

        # 2. Find matching Semgrep rule files
        rule_files = find_semgrep_rules(cwe_code, RULES_DIR)
        print(f"Found {len(rule_files)} rule(s) for {cwe_code}: {[os.path.basename(r) for r in rule_files]}")

        # 3. Split the C file into BAD/GOOD pairs
        pairs, header = split_file_into_pairs(c_file_path)
        print(f"Found {len(pairs)} BAD/GOOD function pairs in the source file.")
        
        if not pairs:
            print("Error: Could not parse any BAD/GOOD pairs. Check file format.")
            return

        # 4. Run Semgrep and analyze results
        run_semgrep_and_analyze(c_file_path, rule_files, pairs)

if __name__ == '__main__':
    main()
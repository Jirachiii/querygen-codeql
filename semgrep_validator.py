#!/usr/bin/env python3
"""
Validate Semgrep rules against Juliet test cases by checking for False Positives (FP) and False Negatives (FN).
"""

import os
import glob
import re
import subprocess
import json
from typing import List, Dict, Tuple, Optional

# --- Configuration ---
SOURCE_DIR = "CWEs"
RULES_DIR = "gpt-generated/semgrep/with-diff"
C_EXTENSION = "*.c*"
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

def find_matching_files(cwe_code: str, rules_dir: str) -> List[str]:
    """Finds all YAML rule files matching the CWE code in the rules directory."""
    # Search recursively for files starting with the CWE code
    search_pattern = os.path.join(rules_dir, f"**/{cwe_code}*{C_EXTENSION}")
    rule_files = glob.glob(search_pattern, recursive=True)
    return rule_files

from typing import Tuple, List, Dict

def split_file_into_region(file_path: str) -> Tuple[List[Dict], str]:
    """
    Splits a Juliet test file into a dictionary grouping the BAD and GOOD regions.
    Returns IMMEDIATELY upon finding the first complete pair (ignoring main).
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    header_lines = []
    
    # Initialize the single pair object for this file
    current_pair = {
        'filepath': file_path
    }
    
    # State tracking
    mode = 'header'
    nesting_depth = 0
    block_lines = []
    block_start_line = 0
    
    for i, line in enumerate(lines):
        line_num = i + 1
        stripped = line.strip()

        # 1. Check for State Transitions
        if mode in ['header', 'gap']:
            if stripped.startswith('#ifndef OMITBAD'):
                mode = 'bad'
                nesting_depth = 1
                block_start_line = line_num + 1
                block_lines = []
                continue
            
            elif stripped.startswith('#ifndef OMITGOOD'):
                mode = 'good'
                nesting_depth = 1
                block_start_line = line_num + 1
                block_lines = []
                continue
            
            elif mode == 'header':
                header_lines.append(line)

        # 2. Process Block Content
        elif mode in ['bad', 'good']:
            if stripped.startswith('#if'):
                nesting_depth += 1
            elif stripped.startswith('#endif'):
                nesting_depth -= 1
            
            # Check if we have closed the block
            if nesting_depth == 0:
                # Save the region
                region_data = {
                    'start_line': block_start_line,
                    'end_line': line_num - 1,
                    'code': "".join(block_lines).strip()
                }
                current_pair[mode] = region_data
                
                # Check immediately if we have a full pair. 
                # If so, return NOW to avoid overwriting with main().
                if 'bad' in current_pair and 'good' in current_pair:
                    return [current_pair], "".join(header_lines).strip()
                # --- FIX END ---

                # Reset state
                mode = 'gap'
                block_lines = []
            else:
                block_lines.append(line)

    # Fallback: If we reach here, we never found a complete pair
    return [], ""

def split_file_into_pairs(filepath: str) -> Tuple[List[Dict], str]:
    """
    Splits file content into BAD/GOOD function pairs and tracks their line numbers.
    The header is everything before the first function.
    """
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.splitlines()
    pairs = []
    current_pair = {
        'filepath': filepath
    }
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

def run_semgrep_and_analyze(test_dir: str, rule_files: List[str], pairs: List[Dict]) -> Tuple[int, int, int, int]:
    """
    Runs Semgrep and returns analysis metrics.
    
    Returns: 
        (fn_count, fp_count, total_findings, outside_findings)
    """
    fn_count = 0
    fp_count = 0
    total_findings = 0
    outside_findings = 0

    if not rule_files:
        print("  Warning: No rules provided.")
        return 0, 0, 0, 0

    # Build the semgrep command
    command = ['semgrep']
    for rule in rule_files:
        command.extend(['--config', rule])
    
    # Force scan of all files (ignoring .gitignore)
    command.append('--no-git-ignore')
    
    command.extend([test_dir, '--json'])

    try:
        # Execute Semgrep
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if process.returncode not in [0, 1]:
            print(f"  Error: Semgrep failed (Exit Code {process.returncode})")
            return 0, 0, 0, 0
        
        # Parse JSON output
        semgrep_results = json.loads(process.stdout)
        findings = semgrep_results.get('results', [])
        total_findings = len(findings)
        
        # Track which findings have been "claimed" by a valid region
        claimed_finding_indices = set()
        
        for pair in pairs:
            file_path = pair['filepath']
            
            # Get findings specifically for this file to speed up checking
            # (In a large scan, filtering this first is more efficient)
            file_findings_indices = [i for i, f in enumerate(findings) if f['path'] in file_path or file_path in f['path']]
            
            # --- Check BAD Region (Expect Findings) ---
            bad_func = pair.get('bad')
            if bad_func:
                bad_region_findings = []
                for idx in file_findings_indices:
                    f = findings[idx]
                    if bad_func['start_line'] <= f['start']['line'] <= bad_func['end_line']:
                        bad_region_findings.append(idx)
                
                # Logic: If NO findings in bad region -> False Negative
                if not bad_region_findings:
                    fn_count += 1
                else:
                    # Mark these findings as "accounted for"
                    claimed_finding_indices.update(bad_region_findings)

            # --- Check GOOD Region (Expect NO Findings) ---
            good_func = pair.get('good')
            if good_func:
                good_region_findings = []
                for idx in file_findings_indices:
                    f = findings[idx]
                    if good_func['start_line'] <= f['start']['line'] <= good_func['end_line']:
                        good_region_findings.append(idx)
                
                # Logic: If YES findings in good region -> False Positive
                if good_region_findings:
                    fp_count += 1
                    # Mark these findings as "accounted for" (even though they are FPs, they are inside a region)
                    claimed_finding_indices.update(good_region_findings)

        # Calculate findings that never matched a Bad or Good region
        outside_findings_list = [f for i, f in enumerate(findings) if i not in claimed_finding_indices]
        outside_findings = len(outside_findings_list)

        if outside_findings > 0:
            print(f"\n  [DEBUG] Found {outside_findings} findings outside known BAD/GOOD regions.")
            print("  Here are the first 5 examples to help you debug:")
            for i, f in enumerate(outside_findings_list[:5]):
                path = f['path']
                line = f['start']['line']
                # Extract code snippet if available
                code_snippet = f.get('extra', {}).get('lines', '').strip()
                print(f"    {i+1}. File: {os.path.basename(path)} | Line: {line}")
                print(f"       Code: {code_snippet}")
                print("-" * 40)

    except Exception as e:
        print(f"  Error during analysis: {e}")
        return 0, 0, 0, 0

    return fn_count, fp_count, total_findings, outside_findings

def main():
    """Main execution flow for the validation pipeline."""
    search_pattern = os.path.join(RULES_DIR, f"**/*{YAML_EXTENSION}")
    rule_files = glob.glob(search_pattern, recursive=True)
    rule_files = ['gpt-generated/semgrep/with-diff/CWE114_Process_Control__w32_char_connect_socket_02.yaml']
    # For each C file in the dir
    for rule_file_path in rule_files:
    
        # 1. Get CWE code from the C file
        cwe_code = get_cwe_code(rule_file_path)
        if not cwe_code:
            print(f"Error: Could not extract CWE code from filename: {rule_file_path}")
            return
        print('Processing', cwe_code)
        # Directory with C files for this CWE
        matching_dirs = glob.glob(os.path.join(SOURCE_DIR, cwe_code + '_*'))
        if not matching_dirs:
            print(f"No directory found for {cwe_code}")
            continue
        test_dir = matching_dirs[0]

        # 2. Find matching Semgrep rule files
        c_files = find_matching_files(cwe_code, SOURCE_DIR)
        print(f"Found {len(c_files)} C file(s) for {cwe_code}: {[os.path.basename(r) for r in rule_files]}")

        # 3. Split the C file into BAD/GOOD pairs
        all_pairs = []
        for c_file_path in c_files:
            pairs, header = split_file_into_region(c_file_path)
            all_pairs.extend(pairs)
        print(f"Found {len(all_pairs)} BAD/GOOD region pairs in the source files.")
        
        if not all_pairs:
            print("Error: Could not parse any BAD/GOOD pairs. Check file format.")
            return

        # 4. Run Semgrep and analyze results
        fn, fp, total, outside = run_semgrep_and_analyze(test_dir, [rule_file_path], all_pairs)

        print(f"  Results -> Total Findings: {total}")
        print(f"             False Negatives (Missed Bad Regions): {fn}")
        print(f"             False Positives (Flagged Good Regions): {fp}")
        print(f"             Findings Outside Regions (Header/Main/etc): {outside}")
if __name__ == '__main__':
    main()
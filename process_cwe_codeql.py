#!/usr/bin/env python3
"""
Main pipeline to process CWE directories and generate CodeQL queries.
This script orchestrates the entire workflow:
1. Extract ASTs from all C files in a CWE directory
2. Find common patterns across the ASTs
3. Generate production-ready CodeQL queries using the improved generator
"""

import sys
import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional


def run_command(cmd: List[str], input_data: Optional[str] = None) -> tuple[str, str, int]:
    """
    Run a command and return (stdout, stderr, returncode).
    """
    try:
        if input_data:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=3000
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3000
            )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timeout", 1
    except Exception as e:
        return "", str(e), 1


def extract_cwe_name(directory: str) -> str:
    """Extract CWE name from directory path."""
    basename = os.path.basename(directory.rstrip('/'))
    # Remove 'CWE' prefix and clean up
    name = basename.replace('CWE', '').replace('_', ' ').strip()
    return f"CWE{name}" if name else basename


def process_cwe_directory(cwe_dir: str, output_dir: Optional[str] = None) -> bool:
    """
    Process a single CWE directory:
    1. Extract ASTs from all .c files
    2. Find common patterns
    3. Generate improved CodeQL queries

    Returns True if successful, False otherwise.
    """
    cwe_name = extract_cwe_name(cwe_dir)
    print(f"\n{'='*60}")
    print(f"Processing {cwe_name}")
    print(f"Directory: {cwe_dir}")
    print(f"{'='*60}\n")

    # Check if directory exists
    if not os.path.isdir(cwe_dir):
        print(f"Error: {cwe_dir} is not a valid directory", file=sys.stderr)
        return False

    # Find all .c files (including subdirectories)
    c_files = sorted(Path(cwe_dir).rglob("*.c"))
    if not c_files:
        print(f"No .c files found in {cwe_dir}", file=sys.stderr)
        return False

    print(f"Found {len(c_files)} C files")

    # Create output directory if specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_prefix = os.path.join(output_dir, cwe_name.lower().replace(' ', '_').replace('-', '_'))
    else:
        output_prefix = cwe_name.lower().replace(' ', '_').replace('-', '_')

    # Step 1: Extract ASTs
    print("\nStep 1: Extracting ASTs...")
    ast_file = f"{output_prefix}_asts.json"

    cmd = ["python3", "extract_c_asts.py", cwe_dir]
    stdout, stderr, returncode = run_command(cmd)

    if returncode != 0:
        print(f"Error extracting ASTs: {stderr}", file=sys.stderr)
        return False

    # Save ASTs to file
    with open(ast_file, 'w') as f:
        f.write(stdout)

    print(f"Saved ASTs to {ast_file}")

    # Step 2: Find common patterns
    print("\nStep 2: Finding common patterns...")
    patterns_file = f"{output_prefix}_patterns.json"

    cmd = ["python3", "find_common_patterns.py", ast_file]
    stdout, stderr, returncode = run_command(cmd)

    if returncode != 0:
        print(f"Error finding patterns: {stderr}", file=sys.stderr)
        return False

    # Save patterns to file
    with open(patterns_file, 'w') as f:
        f.write(stdout)

    # Also print stderr for progress info
    if stderr:
        print(stderr)

    print(f"Saved patterns to {patterns_file}")

    # Step 3: Generate CodeQL queries using improved generator
    print("\nStep 3: Generating CodeQL queries (using improved generator)...")
    queries_dir = f"{output_prefix}_codeql_queries"

    cmd = ["python3", "generate_c_codeql.py", patterns_file, cwe_name, queries_dir]
    stdout, stderr, returncode = run_command(cmd)

    if returncode != 0:
        print(f"Error generating CodeQL queries: {stderr}", file=sys.stderr)
        return False

    # Print stderr for stats
    if stderr:
        print(stderr)

    print(f"Saved CodeQL queries to {queries_dir}/")

    # Count generated queries
    if os.path.isdir(queries_dir):
        query_files = list(Path(queries_dir).glob("*.ql"))
        print(f"Generated {len(query_files)} query files")

    # Print summary
    print(f"\n{'='*60}")
    print(f"Successfully processed {cwe_name}")
    print(f"Output files:")
    print(f"  - ASTs:     {ast_file}")
    print(f"  - Patterns: {patterns_file}")
    print(f"  - Queries:  {queries_dir}/")
    print(f"{'='*60}\n")

    return True


def process_all_cwes(cwes_dir: str, output_dir: Optional[str] = None) -> Dict[str, bool]:
    """
    Process all CWE directories in a parent directory.
    Returns a dict of cwe_name -> success status.
    """
    if not os.path.isdir(cwes_dir):
        print(f"Error: {cwes_dir} is not a valid directory", file=sys.stderr)
        return {}

    # Find all subdirectories that look like CWE directories
    cwe_dirs = sorted([d for d in Path(cwes_dir).iterdir()
                      if d.is_dir() and d.name.startswith('CWE')])

    if not cwe_dirs:
        print(f"No CWE directories found in {cwes_dir}", file=sys.stderr)
        return {}

    print(f"Found {len(cwe_dirs)} CWE directories to process")

    results = {}

    for cwe_dir in cwe_dirs:
        cwe_name = extract_cwe_name(str(cwe_dir))
        success = process_cwe_directory(str(cwe_dir), output_dir)
        results[cwe_name] = success

    return results


def print_summary(results: Dict[str, bool]):
    """Print summary of processing results."""
    print("\n" + "="*60)
    print("PROCESSING SUMMARY")
    print("="*60)

    successful = sum(1 for success in results.values() if success)
    failed = len(results) - successful

    print(f"\nTotal CWEs processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed CWEs:")
        for cwe_name, success in results.items():
            if not success:
                print(f"  - {cwe_name}")

    print("\n" + "="*60 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python process_cwe_codeql.py <cwe_directory> [output_directory]")
        print("   or: python process_cwe_codeql.py --all <cwes_parent_directory> [output_directory]")
        print("")
        print("Examples:")
        print("  python process_cwe_codeql.py CWEs/CWE226_Sensitive_Information_Uncleared_Before_Release")
        print("  python process_cwe_codeql.py --all CWEs/ output/")
        print("")
        print("Note: This script uses the improved CodeQL generator for production-ready queries.")
        sys.exit(1)

    if sys.argv[1] == '--all':
        if len(sys.argv) < 3:
            print("Error: --all requires a parent directory containing CWE subdirectories")
            sys.exit(1)

        cwes_dir = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 else None

        results = process_all_cwes(cwes_dir, output_dir)
        print_summary(results)

    else:
        cwe_dir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None

        success = process_cwe_directory(cwe_dir, output_dir)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
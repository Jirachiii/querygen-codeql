#!/usr/bin/env python3
"""
Script to separate CWE test case files into BAD and GOOD variants.
Splits files with OMITBAD/OMITGOOD sections into two separate C files.
Can process individual files or batch process from a markdown file listing.
"""

import re
import sys
import os
from pathlib import Path


def extract_paths_from_markdown(markdown_file):
    """
    Extract file paths from a markdown file.
    Looks for lines matching "- Path: <filepath>"
    
    Args:
        markdown_file: Path to the markdown file
        
    Returns:
        List of file paths found in the markdown file
    """
    markdown_path = Path(markdown_file)
    
    if not markdown_path.exists():
        print(f"Error: Markdown file '{markdown_file}' not found")
        return []
    
    with open(markdown_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Regex to match "- Path: <filepath>"
    path_pattern = r'^\s*-\s*Path:\s*`?([^`\n]+?)`?\s*$'
    paths = re.findall(path_pattern, content, re.MULTILINE)
    
    print(f"Found {len(paths)} file paths in markdown file")
    return paths


def separate_cwe_file(input_file, base_dir=None, output_dir=None):
    """
    Separates a CWE test case file into BAD and GOOD variants.
    
    Args:
        input_file: Path to the input C file
        base_dir: Base directory for relative paths (optional)
        output_dir: Directory to write output files (optional, defaults to same as input)
    """
    # Handle relative paths with base_dir
    if base_dir and not os.path.isabs(input_file):
        input_path = Path(base_dir) / input_file
    else:
        input_path = Path(input_file)
    
    if not input_path.exists():
        print(f"Error: File '{input_path}' not found")
        return False
    
    # Read the input file
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract base filename without extension
    base_name = input_path.stem
    
    # Create output filenames
    bad_filename = f"{base_name}_bad{input_path.suffix}"
    good_filename = f"{base_name}_good{input_path.suffix}"
    
    # Create BAD version
    bad_content = create_bad_version(content)
    
    # Create GOOD version
    good_content = create_good_version(content)
    
    # Determine output directory
    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = input_path.parent
    
    # Write output files
    with open(out_dir / bad_filename, 'w', encoding='utf-8') as f:
        f.write(bad_content)
    print(f"Created: {out_dir / bad_filename}")
    
    with open(out_dir / good_filename, 'w', encoding='utf-8') as f:
        f.write(good_content)
    print(f"Created: {out_dir / good_filename}")
    
    return True


def create_bad_version(content):
    """Creates the BAD version by removing OMITBAD guards and GOOD code."""
    
    # Remove the #ifndef OMITBAD and #endif /* OMITBAD */ around bad function
    bad_pattern = r'#ifndef OMITBAD\n(.*?)#endif /\* OMITBAD \*/'
    bad_match = re.search(bad_pattern, content, re.DOTALL)
    
    if bad_match:
        bad_function = bad_match.group(1)
    else:
        bad_function = ""
    
    # Remove entire OMITGOOD section
    content_without_good = re.sub(
        r'#ifndef OMITGOOD.*?#endif /\* OMITGOOD \*/',
        '',
        content,
        flags=re.DOTALL
    )
    
    # Remove OMITBAD guards but keep the function
    content_with_bad = re.sub(
        r'#ifndef OMITBAD\n',
        '',
        content_without_good
    )
    content_with_bad = re.sub(
        r'#endif /\* OMITBAD \*/',
        '',
        content_with_bad
    )
    
    # Update main function to only call bad
    content_with_bad = re.sub(
        r'#ifndef OMITGOOD.*?#endif /\* OMITGOOD \*/',
        '',
        content_with_bad,
        flags=re.DOTALL
    )
    content_with_bad = re.sub(
        r'#ifndef OMITBAD\n',
        '',
        content_with_bad
    )
    content_with_bad = re.sub(
        r'#endif /\* OMITBAD \*/',
        '',
        content_with_bad
    )
    
    return content_with_bad.strip() + '\n'


def create_good_version(content):
    """Creates the GOOD version by removing OMITGOOD guards and BAD code."""
    
    # Remove entire OMITBAD section
    content_without_bad = re.sub(
        r'#ifndef OMITBAD.*?#endif /\* OMITBAD \*/',
        '',
        content,
        flags=re.DOTALL
    )
    
    # Remove OMITGOOD guards but keep the function
    content_with_good = re.sub(
        r'#ifndef OMITGOOD\n',
        '',
        content_without_bad
    )
    content_with_good = re.sub(
        r'#endif /\* OMITGOOD \*/',
        '',
        content_with_good
    )
    
    return content_with_good.strip() + '\n'


def process_markdown_file(markdown_file, base_dir=None, output_dir=None):
    """
    Process all files listed in a markdown file.
    
    Args:
        markdown_file: Path to markdown file containing file paths
        base_dir: Base directory for relative paths in markdown
        output_dir: Directory to write output files (optional)
        
    Returns:
        Tuple of (successful_count, failed_count)
    """
    paths = extract_paths_from_markdown(markdown_file)
    
    if not paths:
        print("No file paths found in markdown file")
        return 0, 0
    
    successful = 0
    failed = 0
    failed_files = []
    
    for i, file_path in enumerate(paths, 1):
        print(f"\n[{i}/{len(paths)}] Processing: {file_path}")
        try:
            if separate_cwe_file(file_path, base_dir, output_dir):
                successful += 1
            else:
                failed += 1
                failed_files.append(file_path)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            failed += 1
            failed_files.append(file_path)
    
    print(f"\n{'='*60}")
    print(f"Processing complete!")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    
    if failed_files:
        print(f"\nFailed files:")
        for f in failed_files:
            print(f"  - {f}")
    
    return successful, failed


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Separate CWE test case files into BAD and GOOD variants',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single file
  python separate_cwe_functions.py input.c
  
  # Process files listed in a markdown file
  python separate_cwe_functions.py --markdown cwe_test_samples.md --base-dir /path/to/CWEs
  
  # Process with custom output directory
  python separate_cwe_functions.py input.c --output-dir ./separated
  
  # Batch process with custom output
  python separate_cwe_functions.py --markdown samples.md --base-dir ./CWEs --output-dir ./output
        """
    )
    
    parser.add_argument('input_file', nargs='?', 
                       help='Input C/C++ file to process (not needed with --markdown)')
    parser.add_argument('--markdown', '-m', 
                       help='Markdown file containing list of files to process')
    parser.add_argument('--base-dir', '-b', 
                       help='Base directory for relative paths in markdown file')
    parser.add_argument('--output-dir', '-o', 
                       help='Output directory for separated files')
    
    args = parser.parse_args()
    
    # Check if we're processing markdown or single file
    if args.markdown:
        # Batch processing from markdown
        if not os.path.exists(args.markdown):
            print(f"Error: Markdown file '{args.markdown}' not found")
            sys.exit(1)
        
        successful, failed = process_markdown_file(
            args.markdown, 
            args.base_dir, 
            args.output_dir
        )
        
        if failed > 0:
            sys.exit(1)
    else:
        # Single file processing
        if not args.input_file:
            parser.print_help()
            sys.exit(1)
        
        success = separate_cwe_file(
            args.input_file, 
            args.base_dir, 
            args.output_dir
        )
        
        if success:
            print("\nSuccessfully separated into BAD and GOOD versions!")
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
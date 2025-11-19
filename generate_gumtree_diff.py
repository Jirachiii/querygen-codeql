#!/usr/bin/env python3
"""
Script to generate GumTree textdiff outputs for CWE BAD/GOOD file pairs.
For each _bad.c/_bad.cpp file, finds the corresponding _good file and runs gumtree textdiff.
"""

import os
import sys
import subprocess
from pathlib import Path
import argparse

GUMTREE = '/Users/trangdang/Documents/vscode/codeql/gumtree-4.0.0-beta4/bin/gumtree'

def find_bad_files(directory):
    """
    Find all files ending with _bad.c or _bad.cpp in the directory.
    
    Args:
        directory: Path to the directory to search
        
    Returns:
        List of Path objects for bad files
    """
    dir_path = Path(directory)
    
    if not dir_path.exists():
        print(f"Error: Directory '{directory}' not found")
        return []
    
    if not dir_path.is_dir():
        print(f"Error: '{directory}' is not a directory")
        return []
    
    # Find all _bad.c and _bad.cpp files
    bad_files = []
    bad_files.extend(dir_path.glob("*_bad.c"))
    bad_files.extend(dir_path.glob("*_bad.cpp"))
    
    # Sort for consistent ordering
    bad_files.sort()
    
    print(f"Found {len(bad_files)} bad files in '{directory}'")
    return bad_files


def get_good_file(bad_file):
    """
    Get the corresponding good file path by replacing _bad with _good.
    
    Args:
        bad_file: Path to the bad file
        
    Returns:
        Path to the corresponding good file
    """
    bad_str = str(bad_file)
    
    # Replace _bad.c with _good.c or _bad.cpp with _good.cpp
    if bad_str.endswith('_bad.c'):
        good_str = bad_str.replace('_bad.c', '_good.c')
    elif bad_str.endswith('_bad.cpp'):
        good_str = bad_str.replace('_bad.cpp', '_good.cpp')
    else:
        # Shouldn't happen, but handle it anyway
        good_str = bad_str.replace('_bad', '_good')
    
    return Path(good_str)


def get_output_file(bad_file):
    """
    Get the output file path by removing _bad suffix.
    
    Args:
        bad_file: Path to the bad file
        
    Returns:
        Path for the output txt file
    """
    bad_str = str(bad_file)
    
    # Remove _bad but keep the extension, then add .txt
    if bad_str.endswith('_bad.c'):
        output_str = bad_str.replace('_bad.c', '.txt')
    elif bad_str.endswith('_bad.cpp'):
        output_str = bad_str.replace('_bad.cpp', '.txt')
    else:
        # Fallback
        output_str = bad_str.replace('_bad', '') + '.txt'
    
    return Path(output_str)


def run_gumtree_diff(bad_file, good_file, output_file, dry_run=False):
    """
    Run gumtree textdiff command on a BAD/GOOD file pair.
    
    Args:
        bad_file: Path to the bad file
        good_file: Path to the good file
        output_file: Path to save the diff output
        dry_run: If True, only print the command without executing
        
    Returns:
        True if successful, False otherwise
    """
    # Build the gumtree command
    cmd = [
        GUMTREE,
        'textdiff',
        str(bad_file),
        str(good_file),
        '-o',
        str(output_file)
    ]
    
    if dry_run:
        print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
        return True
    
    try:
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout per file
        )
        
        if result.returncode == 0:
            return True
        else:
            print(f"  Warning: gumtree returned code {result.returncode}")
            if result.stderr:
                print(f"  Error: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"  Error: Command timed out after 30 seconds")
        return False
    except FileNotFoundError:
        print(f"  Error: gumtree command not found. Is GumTree installed and in PATH?")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def process_directory(directory, output_dir=None, dry_run=False):
    """
    Process all BAD/GOOD file pairs in a directory.
    
    Args:
        directory: Directory containing the split files
        output_dir: Optional directory for output files (defaults to same as input)
        dry_run: If True, only print what would be done
        
    Returns:
        Tuple of (successful_count, failed_count)
    """
    bad_files = find_bad_files(directory)
    
    if not bad_files:
        print("No bad files found to process")
        return 0, 0
    
    # Determine output directory
    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {out_dir}")
    else:
        out_dir = Path(directory)
        print(f"Output directory: {out_dir} (same as input)")
    
    successful = 0
    failed = 0
    missing_good_files = []
    
    print(f"\n{'='*70}")
    print("Starting GumTree diff generation...")
    print(f"{'='*70}\n")
    
    for i, bad_file in enumerate(bad_files, 1):
        print(f"[{i}/{len(bad_files)}] Processing: {bad_file.name}")
        
        # Get corresponding good file
        good_file = get_good_file(bad_file)
        
        # Check if good file exists
        if not good_file.exists():
            print(f"  Error: Good file not found: {good_file.name}")
            failed += 1
            missing_good_files.append(good_file.name)
            continue
        
        # Get output file path
        output_file = out_dir / get_output_file(bad_file).name
        
        print(f"  Bad:    {bad_file.name}")
        print(f"  Good:   {good_file.name}")
        print(f"  Output: {output_file.name}")
        
        # Run gumtree diff
        if run_gumtree_diff(bad_file, good_file, output_file, dry_run):
            print(f"  ✓ Success")
            successful += 1
        else:
            print(f"  ✗ Failed")
            failed += 1
        
        print()  # Blank line between files
    
    # Print summary
    print(f"{'='*70}")
    print("Processing complete!")
    print(f"{'='*70}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    
    if missing_good_files:
        print(f"\nMissing good files ({len(missing_good_files)}):")
        for fname in missing_good_files:
            print(f"  - {fname}")
    
    return successful, failed


def check_gumtree_installed():
    """
    Check if gumtree is installed and accessible.
    
    Returns:
        True if gumtree is available, False otherwise
    """
    try:
        result = subprocess.run(
            [GUMTREE, '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Generate GumTree textdiff outputs for CWE BAD/GOOD file pairs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all files in a directory
  python generate_gumtree_diffs.py ./separated_files
  
  # Specify output directory
  python generate_gumtree_diffs.py ./separated_files --output-dir ./diffs
  
  # Dry run to see what would be executed
  python generate_gumtree_diffs.py ./separated_files --dry-run
  
  # Check if GumTree is installed
  python generate_gumtree_diffs.py --check-gumtree

The script will:
1. Find all *_bad.c and *_bad.cpp files
2. For each bad file, find the corresponding *_good file
3. Run: gumtree textdiff <bad_file> <good_file> -o <output.txt>
4. Save output as the filename without _bad or _good suffix

Example:
  Input files:  CWE195_..._01_bad.c and CWE195_..._01_good.c
  Output file:  CWE195_..._01.txt
        """
    )
    
    parser.add_argument('directory', nargs='?',
                       help='Directory containing the separated BAD/GOOD files')
    parser.add_argument('--output-dir', '-o',
                       help='Output directory for diff files (defaults to input directory)')
    parser.add_argument('--dry-run', '-n', action='store_true',
                       help='Print commands without executing them')
    parser.add_argument('--check-gumtree', action='store_true',
                       help='Check if GumTree is installed and exit')
    
    args = parser.parse_args()
    
    # Handle --check-gumtree
    if args.check_gumtree:
        print("Checking for GumTree installation...")
        if check_gumtree_installed():
            print("✓ GumTree is installed and accessible")
            try:
                result = subprocess.run(
                    [GUMTREE, '--version'],
                    capture_output=True,
                    text=True
                )
                print(f"Version info: {result.stdout.strip()}")
            except:
                pass
            sys.exit(0)
        else:
            print("✗ GumTree not found")
            print("\nPlease install GumTree:")
            print("  https://github.com/GumTreeDiff/gumtree")
            sys.exit(1)
    
    # Require directory argument if not checking gumtree
    if not args.directory:
        parser.print_help()
        sys.exit(1)
    
    # Check if GumTree is installed (unless dry-run)
    if not args.dry_run and not check_gumtree_installed():
        print("Error: GumTree is not installed or not in PATH")
        print("\nPlease install GumTree:")
        print("  https://github.com/GumTreeDiff/gumtree")
        print("\nOr run with --dry-run to see what commands would be executed")
        sys.exit(1)
    
    # Process the directory
    successful, failed = process_directory(
        args.directory,
        args.output_dir,
        args.dry_run
    )
    
    # Exit with error code if any failed
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Extract AST representations from C files using GumTree.
This script processes C files and extracts their AST structure.
"""

import sys
import os
import json
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple
from pathlib import Path


GUMTREE_PATH = "/Users/trangdang/Documents/vscode/codeql/gumtree-4.0.0-beta4/bin/gumtree"


def extract_ast_from_c_file(file_path: str) -> Optional[Dict]:
    """
    Extract AST from a C file using GumTree.
    Returns a dictionary representation of the AST.
    """
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist", file=sys.stderr)
        return None

    # Create a temporary file for the XML output
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
        tmp_xml = tmp.name

    try:
        # Run GumTree to generate JSON AST for the C file
        # Use 'parse' command with JSON format (more reliable than XML)
        cmd = [GUMTREE_PATH, "parse", "-f", "JSON", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            print(f"Error running GumTree on {file_path}: {result.stderr}", file=sys.stderr)
            return None

        # GumTree outputs JSON to stdout
        json_content = result.stdout

        # Parse the JSON
        try:
            ast_json = json.loads(json_content)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON for {file_path}: {e}", file=sys.stderr)
            return None

        # Read the source code
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()

        # Extract the root node
        root_node = ast_json.get('root', {})

        # Convert to our format and add source snippets
        ast_with_snippets = add_snippets_to_ast(root_node, source_code)

        ast_dict = {
            'file_path': file_path,
            'source': source_code,
            'ast': ast_with_snippets
        }

        return ast_dict

    except subprocess.TimeoutExpired:
        print(f"Timeout processing {file_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
        return None
    finally:
        # Clean up temp file
        if os.path.exists(tmp_xml):
            os.unlink(tmp_xml)


def add_snippets_to_ast(node: Dict, source: str) -> Dict:
    """
    Add source code snippets to AST nodes based on pos and length attributes.
    GumTree JSON format already has the right structure, we just add snippets.
    """
    result = {
        'type': node.get('type', ''),
        'label': node.get('label', ''),
    }

    # Extract position and length if available
    pos_str = node.get('pos')
    length_str = node.get('length')

    if pos_str is not None and length_str is not None:
        try:
            pos = int(pos_str)
            length = int(length_str)
            result['pos'] = pos
            result['length'] = length

            # Extract source snippet
            if 0 <= pos < len(source) and length > 0 and pos + length <= len(source):
                snippet = source[pos:pos + length]
                result['snippet'] = snippet
        except (ValueError, IndexError):
            pass

    # Process children recursively
    children = node.get('children', [])
    if children:
        result['children'] = [add_snippets_to_ast(child, source) for child in children]

    return result


def extract_function_asts(ast_dict: Dict, function_pattern: str = "_bad") -> List[Dict]:
    """
    Extract ASTs of functions matching a pattern (e.g., functions ending with '_bad').
    Returns a list of function AST subtrees.
    """
    functions = []

    def find_functions(node: Dict, depth: int = 0):
        """Recursively find function declarations."""
        node_type = node.get('type', '')

        # In C AST, functions are typically 'FunctionDefinition' or similar
        if 'function' in node_type.lower() or node_type == 'FunctionDefinition':
            # Check if function name matches pattern
            snippet = node.get('snippet', '')
            label = node.get('label', '')

            if function_pattern in snippet or function_pattern in label:
                functions.append(node)

        # Recurse into children
        for child in node.get('children', []):
            find_functions(child, depth + 1)

    find_functions(ast_dict.get('ast', {}))
    return functions


def normalize_ast_for_comparison(node: Dict, keep_identifiers: bool = False) -> Dict:
    """
    Normalize AST for pattern matching by removing specific values.
    Keeps structure but abstracts away concrete values unless specified.
    """
    normalized = {
        'type': node.get('type', '')
    }

    # Keep label only if it's a keyword or operator
    label = node.get('label', '')
    if label and (is_keyword_or_operator(label) or keep_identifiers):
        normalized['label'] = label

    # Recurse into children
    children = []
    for child in node.get('children', []):
        children.append(normalize_ast_for_comparison(child, keep_identifiers))

    if children:
        normalized['children'] = children

    return normalized


def is_keyword_or_operator(text: str) -> bool:
    """Check if text is a C keyword or operator."""
    keywords = {
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
        'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
        'struct', 'union', 'enum', 'const', 'static', 'extern', 'volatile',
        'void', 'int', 'char', 'float', 'double', 'long', 'short', 'unsigned',
        'signed', '+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=',
        '&&', '||', '!', '&', '|', '^', '~', '<<', '>>', '=', '+=', '-=',
        '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '++', '--'
    }
    return text.lower() in keywords


def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_c_asts.py <c_file1> [c_file2 ...]")
        print("   or: python extract_c_asts.py <directory>")
        sys.exit(1)

    input_path = sys.argv[1]

    # Determine if input is file or directory
    if os.path.isfile(input_path):
        files = [input_path]
    elif os.path.isdir(input_path):
        # Find all .c files in directory (including subdirectories)
        files = sorted(Path(input_path).rglob("*.c"))
        files = [str(f) for f in files]
    else:
        print(f"Error: {input_path} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)

    results = []

    for file_path in files:
        print(f"Processing {file_path}...", file=sys.stderr)
        ast_dict = extract_ast_from_c_file(file_path)

        if ast_dict:
            results.append(ast_dict)
        else:
            print(f"Failed to extract AST from {file_path}", file=sys.stderr)

    # Output results as JSON
    with open('output/extracted_ast.json','w') as f:
        json.dump(results, f, indent=4)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

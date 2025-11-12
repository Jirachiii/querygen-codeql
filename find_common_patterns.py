#!/usr/bin/env python3
"""
Find common structural patterns across multiple ASTs.
This module identifies the "skeleton" or common structure shared by multiple C files.
"""

import sys
import json
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter


def compute_ast_signature(node: Dict, depth: int = 0, max_depth: int = 10) -> str:
    """
    Compute a signature string for an AST node that captures its structure.
    Used to identify similar patterns across different ASTs.
    """
    if depth > max_depth:
        return "..."

    node_type = node.get('type', 'unknown')
    label = node.get('label', '')

    # Create signature with type and label (if keyword/operator)
    sig_parts = [node_type]
    if label and is_structural_element(label):
        sig_parts.append(f":{label}")

    # Add children signatures
    children = node.get('children', [])
    if children:
        child_sigs = [compute_ast_signature(child, depth + 1, max_depth) for child in children]
        sig_parts.append(f"({','.join(child_sigs)})")

    return ''.join(sig_parts)


def is_structural_element(text: str) -> bool:
    """
    Check if text is a structural element (keyword, operator) that should be
    preserved in the pattern signature.
    """
    structural = {
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
        'break', 'continue', 'return', 'goto', 'sizeof',
        'struct', 'union', 'enum',
        '+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=',
        '&&', '||', '!', '&', '|', '^', '~', '=',
        '++', '--', '->', '.', '[', ']', '(', ')', '{', '}'
    }
    return text.lower() in structural or text in structural


def extract_all_subtrees(node: Dict, min_size: int = 3) -> List[Tuple[str, Dict]]:
    """
    Extract all subtrees from an AST that are at least min_size nodes deep.
    Returns list of (signature, subtree) tuples.
    """
    subtrees = []

    def count_nodes(n: Dict) -> int:
        """Count total nodes in subtree."""
        return 1 + sum(count_nodes(child) for child in n.get('children', []))

    def extract_recursive(n: Dict):
        """Recursively extract subtrees."""
        node_count = count_nodes(n)
        if node_count >= min_size:
            sig = compute_ast_signature(n)
            subtrees.append((sig, n))

        # Recurse into children
        for child in n.get('children', []):
            extract_recursive(child)

    extract_recursive(node)
    return subtrees


def find_common_subtrees(asts: List[Dict], min_occurrence: int = 2) -> List[Tuple[str, int, List[Dict]]]:
    """
    Find subtree patterns that occur in at least min_occurrence ASTs.
    Returns list of (signature, count, example_nodes) tuples.
    """
    # Collect all subtrees from all ASTs
    signature_to_nodes = defaultdict(list)
    signature_to_files = defaultdict(set)

    for i, ast_dict in enumerate(asts):
        ast = ast_dict.get('ast', {})
        file_path = ast_dict.get('file_path', f'file_{i}')

        subtrees = extract_all_subtrees(ast, min_size=3)

        for sig, node in subtrees:
            signature_to_nodes[sig].append(node)
            signature_to_files[sig].add(file_path)

    # Filter to patterns that occur in multiple files
    common_patterns = []

    for sig, nodes in signature_to_nodes.items():
        file_count = len(signature_to_files[sig])
        if file_count >= min_occurrence:
            # Take up to 3 example nodes
            examples = nodes[:3]
            common_patterns.append((sig, file_count, examples))

    # Sort by frequency (most common first)
    common_patterns.sort(key=lambda x: x[1], reverse=True)

    return common_patterns


def extract_control_flow_patterns(node: Dict) -> List[Dict]:
    """
    Extract control flow patterns (if, for, while, etc.) from AST.
    These are typically the most interesting patterns for security vulnerabilities.
    """
    patterns = []

    node_type = node.get('type', '')
    node_type_lower = node_type.lower()

    # Check if this is a control flow node
    control_keywords = {'if', 'for', 'while', 'switch', 'case'}
    is_control_flow = any(kw in node_type_lower for kw in control_keywords)

    # Also check label
    label = node.get('label', '').lower()
    if any(kw in label for kw in control_keywords):
        is_control_flow = True

    if is_control_flow:
        patterns.append(node)

    # Recurse into children
    for child in node.get('children', []):
        patterns.extend(extract_control_flow_patterns(child))

    return patterns


def extract_function_call_patterns(node: Dict) -> List[Dict]:
    """
    Extract function call patterns from AST.
    Important for detecting dangerous function usage.
    """
    calls = []

    node_type = node.get('type', '')
    node_type_lower = node_type.lower()

    # Check if this is a function call
    if 'call' in node_type_lower or 'invocation' in node_type_lower:
        calls.append(node)

    # Recurse into children
    for child in node.get('children', []):
        calls.extend(extract_function_call_patterns(child))

    return calls


def find_common_function_calls(asts: List[Dict]) -> Dict[str, int]:
    """
    Find function calls that appear across multiple files.
    Returns dict of function_name -> count.
    """
    function_names = []

    for ast_dict in asts:
        ast = ast_dict.get('ast', {})
        calls = extract_function_call_patterns(ast)

        for call in calls:
            # Try to extract function name from snippet or label
            snippet = call.get('snippet', '')
            label = call.get('label', '')

            # Simple heuristic: extract identifier before '('
            for text in [snippet, label]:
                if '(' in text:
                    func_name = text.split('(')[0].strip()
                    if func_name and func_name[0].isalpha():
                        function_names.append(func_name)

    # Count occurrences
    return dict(Counter(function_names))


def build_skeleton_pattern(common_subtrees: List[Tuple[str, int, List[Dict]]],
                          top_k: int = 10) -> List[Dict]:
    """
    Build a skeleton pattern from the most common subtrees.
    Returns a list of pattern dictionaries suitable for Semgrep generation.
    """
    patterns = []

    for i, (sig, count, examples) in enumerate(common_subtrees[:top_k]):
        # Take the first example as representative
        example_node = examples[0] if examples else {}

        pattern = {
            'signature': sig,
            'occurrence_count': count,
            'ast_structure': example_node,
            'pattern_type': classify_pattern(example_node)
        }

        patterns.append(pattern)

    return patterns


def classify_pattern(node: Dict) -> str:
    """
    Classify the type of pattern (control flow, function call, etc.).
    """
    node_type = node.get('type', '').lower()
    label = node.get('label', '').lower()
    snippet = node.get('snippet', '').lower()

    if any(kw in node_type or kw in label or kw in snippet
           for kw in ['if', 'while', 'for', 'switch']):
        return 'control_flow'
    elif 'call' in node_type or 'invocation' in node_type:
        return 'function_call'
    elif 'assignment' in node_type or '=' in label:
        return 'assignment'
    elif 'declaration' in node_type:
        return 'declaration'
    else:
        return 'other'


def analyze_vulnerability_patterns(asts: List[Dict]) -> Dict:
    """
    Analyze ASTs to identify common vulnerability patterns.
    Returns a comprehensive analysis including:
    - Common subtrees
    - Function call patterns
    - Control flow patterns
    """
    print(f"Analyzing {len(asts)} ASTs...", file=sys.stderr)

    # Find common subtrees
    common_subtrees = find_common_subtrees(asts, min_occurrence=max(2, len(asts) // 2))
    print(f"Found {len(common_subtrees)} common patterns", file=sys.stderr)

    # Find common function calls
    common_calls = find_common_function_calls(asts)
    print(f"Found {len(common_calls)} distinct function calls", file=sys.stderr)

    # Build skeleton patterns
    skeleton = build_skeleton_pattern(common_subtrees, top_k=15)

    # Combine results
    analysis = {
        'num_files': len(asts),
        'common_subtrees': [
            {
                'signature': sig,
                'occurrence_count': count,
                'pattern_type': classify_pattern(examples[0]) if examples else 'unknown'
            }
            for sig, count, examples in common_subtrees[:20]
        ],
        'common_function_calls': [
            {'function': name, 'count': count}
            for name, count in sorted(common_calls.items(), key=lambda x: x[1], reverse=True)[:20]
        ],
        'skeleton_patterns': skeleton
    }

    return analysis


def main():
    if len(sys.argv) < 2:
        print("Usage: python find_common_patterns.py <ast_json_file>")
        print("  Where ast_json_file is the output from extract_c_asts.py")
        sys.exit(1)

    ast_file = sys.argv[1]

    # Load ASTs from JSON file
    with open(ast_file, 'r') as f:
        asts = json.load(f)

    if not asts:
        print("No ASTs found in input file", file=sys.stderr)
        sys.exit(1)

    # Analyze patterns
    analysis = analyze_vulnerability_patterns(asts)

    # Output analysis as JSON
    with open('output/common_patterns.json', 'w') as f:
        json.dump(analysis, f, indent=2)
    print(json.dumps(analysis, indent=2))


if __name__ == "__main__":
    main()

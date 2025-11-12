#!/usr/bin/env python3
"""
Improved CodeQL query generator that creates more meaningful, testable patterns.
Focuses on:
1. Dangerous function usage patterns
2. Missing security functions (e.g., ALLOCA without SecureZeroMemory)
3. Common vulnerable code patterns with actual predicates
"""

import sys
import os
import json
import re
from typing import Dict, List, Optional, Set
from collections import Counter


def load_analysis(analysis_file: str) -> Dict:
    """Load pattern analysis from JSON file."""
    with open(analysis_file, 'r') as f:
        return json.load(f)


def extract_meaningful_patterns(analysis: Dict) -> List[Dict]:
    """Extract meaningful patterns from analysis."""
    patterns = []

    # Get function calls
    func_calls = analysis.get('common_function_calls', [])

    # Categorize functions
    dangerous_funcs = []
    security_funcs = []

    for func in func_calls:
        fname = func['function']
        count = func['count']

        # Dangerous functions
        if any(x in fname.lower() for x in ['alloca', 'strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'fgets', 'logonuser']):
            dangerous_funcs.append({'name': fname, 'count': count})

        # Security/cleanup functions
        if any(x in fname.lower() for x in ['securezero', 'memset', 'bzero', 'free', 'close']):
            security_funcs.append({'name': fname, 'count': count})

    patterns.append({
        'type': 'dangerous_functions',
        'functions': dangerous_funcs[:10]  # Top 10
    })

    patterns.append({
        'type': 'security_functions',
        'functions': security_funcs[:5]  # Top 5
    })

    return patterns


def generate_dangerous_function_query(func_info: Dict, cwe_name: str, query_id: str) -> Dict:
    """Generate CodeQL query for dangerous function usage."""
    func_name = func_info['name']

    # Categorize and create appropriate message
    if 'alloca' in func_name.lower():
        message = f"Use of {func_name} allocates memory on stack without bounds checking. Consider using malloc with proper size validation."
        category = "memory_management"
        severity = "warning"
    elif func_name.lower() in ['strcpy', 'strcat', 'sprintf', 'gets']:
        message = f"Use of {func_name} is unsafe and can lead to buffer overflow. Use safer alternatives like strncpy, strncat, snprintf."
        category = "buffer_overflow"
        severity = "error"
    elif 'logonuser' in func_name.lower():
        message = f"Use of {func_name} with sensitive credentials. Ensure passwords are cleared from memory after use."
        category = "sensitive_data"
        severity = "error"
    elif 'fgets' in func_name.lower():
        message = f"Use of {func_name} - ensure proper buffer size and null termination."
        category = "input_validation"
        severity = "warning"
    else:
        message = f"Potentially dangerous function {func_name} detected."
        category = "general"
        severity = "warning"

    return {
        'query_id': query_id,
        'cwe_name': cwe_name,
        'function_name': func_name,
        'message': message,
        'category': category,
        'severity': severity,
        'precision': 'high',
        'query_type': 'dangerous_function'
    }


def generate_missing_cleanup_queries(analysis: Dict, cwe_name: str) -> List[Dict]:
    """
    Generate queries for missing cleanup/security functions.
    E.g., ALLOCA without SecureZeroMemory
    """
    queries = []

    func_calls = analysis.get('common_function_calls', [])
    func_dict = {f['function']: f['count'] for f in func_calls}

    # Check for ALLOCA without SecureZeroMemory
    has_alloca = any('alloca' in f.lower() for f in func_dict.keys())
    has_securezero = any('securezero' in f.lower() for f in func_dict.keys())

    if has_alloca:
        alloca_name = next((f for f in func_dict.keys() if 'alloca' in f.lower()), 'ALLOCA')
        
        query_id = f'{cwe_name.lower().replace(" ", "_")}_alloca_without_cleanup'
        queries.append({
            'query_id': query_id,
            'cwe_name': cwe_name,
            'message': f'Memory allocated with {alloca_name} should be cleared before function return using SecureZeroMemory',
            'category': 'sensitive_data_exposure',
            'severity': 'error',
            'precision': 'high',
            'query_type': 'missing_cleanup',
            'allocation_func': alloca_name,
            'cleanup_func': 'SecureZeroMemory',
            'has_cleanup_func': has_securezero
        })

    # Check for malloc without free
    if 'malloc' in func_dict:
        query_id = f'{cwe_name.lower().replace(" ", "_")}_malloc_without_free'
        queries.append({
            'query_id': query_id,
            'cwe_name': cwe_name,
            'message': 'Memory allocated with malloc should be freed to prevent memory leaks',
            'category': 'memory_leak',
            'severity': 'warning',
            'precision': 'medium',
            'query_type': 'missing_free',
            'allocation_func': 'malloc'
        })

    # Check for LogonUser without password cleanup
    has_logonuser = any('logonuser' in f.lower() for f in func_dict.keys())
    if has_logonuser:
        logonuser_name = next((f for f in func_dict.keys() if 'logonuser' in f.lower()), 'LogonUser')
        
        query_id = f'{cwe_name.lower().replace(" ", "_")}_logonuser_without_cleanup'
        queries.append({
            'query_id': query_id,
            'cwe_name': cwe_name,
            'message': f'Passwords used in {logonuser_name} should be cleared from memory using SecureZeroMemory',
            'category': 'sensitive_data_exposure',
            'severity': 'error',
            'precision': 'high',
            'query_type': 'missing_password_cleanup',
            'auth_func': logonuser_name,
            'cleanup_func': 'SecureZeroMemory'
        })

    return queries


def generate_specific_vulnerability_queries(cwe_name: str, analysis: Dict) -> List[Dict]:
    """Generate CWE-specific queries based on the CWE type."""
    queries = []
    cwe_lower = cwe_name.lower()

    func_calls = analysis.get('common_function_calls', [])
    func_dict = {f['function']: f['count'] for f in func_calls}

    # CWE-226: Sensitive Information Uncleared Before Release
    if '226' in cwe_name or 'sensitive information' in cwe_lower:
        queries.extend([
            {
                'query_id': 'sensitive_info_in_stack_memory',
                'cwe_name': cwe_name,
                'message': 'Sensitive data stored in stack-allocated memory without cleanup',
                'category': 'sensitive_data_exposure',
                'severity': 'error',
                'precision': 'medium',
                'query_type': 'stack_sensitive_data'
            },
            {
                'query_id': 'password_not_cleared',
                'cwe_name': cwe_name,
                'message': 'Password variable not cleared before function return',
                'category': 'sensitive_data_exposure',
                'severity': 'error',
                'precision': 'high',
                'query_type': 'password_not_cleared'
            }
        ])
        # Add this to the generate_specific_vulnerability_patterns function in generate_c_codeql.py

# CWE-123: Write-What-Where Condition
    elif '123' in cwe_name or 'write what where' in cwe_lower:
        queries.extend([
        {
            'query_id': f'{cwe_name.lower().replace(" ", "_")}_unchecked_pointer_write',
            'cwe_name': cwe_name,
            'message': 'Detects pointer writes without validation of address which can lead to write-what-where conditions',
            'severity': 'error',
            'precision': 'high',
            'query_type': 'write_what_where'
#             'query': '''
# import cpp

# from PointerFieldAccess pfa, Assignment assign
# where 
#   assign.getLValue() = pfa and
#   not exists(IfStmt guard | 
#     guard.getCondition().getAChild*() = pfa.getQualifier() and
#     guard.getAChild+() = assign
#   )
# select assign, "Pointer write without validation of address can lead to write-what-where condition"
# '''
        }
    ])

    # CWE-252/253: Unchecked Return Value
    elif '252' in cwe_name or '253' in cwe_name or 'return value' in cwe_lower:
        # Check if fgets is in the function calls
        if any('fgets' in f.lower() for f in func_dict.keys()):
            queries.append({
                'query_id': 'unchecked_fgets_return',
                'cwe_name': cwe_name,
                'message': 'Return value of fgets not checked for NULL',
                'category': 'unchecked_return_value',
                'severity': 'warning',
                'precision': 'high',
                'query_type': 'unchecked_return',
                'function_name': 'fgets'
            })

    return queries


def write_dangerous_function_query(f, query: Dict):
    """Write CodeQL query for dangerous function detection."""
    func_name = query['function_name']
    
    f.write("from FunctionCall fc\n")
    f.write(f"where fc.getTarget().getName() = \"{func_name}\"\n")
    f.write(f"select fc, \"{query['message']}\"\n")


def write_missing_cleanup_query(f, query: Dict):
    """Write CodeQL query for missing cleanup patterns."""
    if query['query_type'] == 'missing_cleanup':
        alloc_func = query['allocation_func']
        cleanup_func = query['cleanup_func']
        
        f.write("import semmle.code.cpp.controlflow.Guards\n\n")
        f.write("from FunctionCall alloc, Function func\n")
        f.write(f"where alloc.getTarget().getName() = \"{alloc_func}\"\n")
        f.write("  and alloc.getEnclosingFunction() = func\n")
        f.write(f"  and not exists(FunctionCall cleanup |\n")
        f.write(f"    cleanup.getTarget().getName() = \"{cleanup_func}\" and\n")
        f.write("    cleanup.getEnclosingFunction() = func\n")
        f.write("  )\n")
        f.write(f"select alloc, \"{query['message']}\"\n")
    
    elif query['query_type'] == 'missing_free':
        f.write("import cpp\n")
        f.write("import semmle.code.cpp.dataflow.DataFlow\n\n")
        f.write("from FunctionCall malloc, Variable v\n")
        f.write("where malloc.getTarget().getName() = \"malloc\"\n")
        f.write("  and v.getAnAssignedValue() = malloc\n")
        f.write("  and not exists(FunctionCall free |\n")
        f.write("    free.getTarget().getName() = \"free\" and\n")
        f.write("    free.getArgument(0) = v.getAnAccess()\n")
        f.write("  )\n")
        f.write(f"select malloc, \"{query['message']}\"\n")
    
    elif query['query_type'] == 'missing_password_cleanup':
        auth_func = query['auth_func']
        cleanup_func = query['cleanup_func']
        
        f.write("from FunctionCall auth, Function func\n")
        f.write(f"where auth.getTarget().getName().matches(\"{auth_func}%\")\n")
        f.write("  and auth.getEnclosingFunction() = func\n")
        f.write(f"  and not exists(FunctionCall cleanup |\n")
        f.write(f"    cleanup.getTarget().getName() = \"{cleanup_func}\" and\n")
        f.write("    cleanup.getEnclosingFunction() = func\n")
        f.write("  )\n")
        f.write(f"select auth, \"{query['message']}\"\n")


def write_specific_vulnerability_query(f, query: Dict):
    """Write CWE-specific vulnerability queries."""
    if query['query_type'] == 'stack_sensitive_data':
        f.write("from LocalVariable v\n")
        f.write("where v.getType().getName().toLowerCase().matches(\"%password%\")\n")
        f.write("  or v.getType().getName().toLowerCase().matches(\"%credential%\")\n")
        f.write("  or v.getName().toLowerCase().matches(\"%password%\")\n")
        f.write("  or v.getName().toLowerCase().matches(\"%pwd%\")\n")
        f.write(f"select v, \"{query['message']}\"\n")
    
    elif query['query_type'] == 'password_not_cleared':
        f.write("import semmle.code.cpp.controlflow.Guards\n\n")
        f.write("from LocalVariable v, Function func\n")
        f.write("where (v.getName().toLowerCase().matches(\"%password%\")\n")
        f.write("       or v.getName().toLowerCase().matches(\"%pwd%\"))\n")
        f.write("  and v.getFunction() = func\n")
        f.write("  and not exists(FunctionCall cleanup |\n")
        f.write("    cleanup.getTarget().getName().matches(\"%Zero%\") and\n")
        f.write("    cleanup.getEnclosingFunction() = func\n")
        f.write("  )\n")
        f.write(f"select v, \"{query['message']}\"\n")
    
    elif query['query_type'] == 'unchecked_return':
        func_name = query['function_name']
        f.write("import cpp\n\n")
        f.write("from FunctionCall fc\n")
        f.write(f"where fc.getTarget().getName() = \"{func_name}\"\n")
        f.write("  and not exists(ExprInVoidContext eivc | eivc.getExpr() = fc)\n")
        f.write("  and not exists(IfStmt is | is.getCondition() = fc)\n")
        f.write("  and not exists(IfStmt is |\n")
        f.write("    is.getCondition().(BinaryOperation).getAnOperand*() = fc\n")
        f.write("  )\n")
        f.write(f"select fc, \"{query['message']}\"\n")
    
    elif query['query_type'] == 'write_what_where':
        f.write("import cpp\n\n")
        f.write("from PointerFieldAccess pfa, Assignment assign\n")
        f.write("where\n")
        f.write("  assign.getLValue() = pfa and\n")
        f.write("  not exists(IfStmt guard |\n")
        f.write("    guard.getCondition().getAChild*() = pfa.getQualifier() and\n")
        f.write("    guard.getAChild+() = assign\n")
        f.write("  )\n")
        f.write(f"select assign, \"{query['message']}\"\n")

def emit_codeql_query_file(query: Dict, filepath: str):
    """Write a single .ql file."""
    with open(filepath, 'w') as f:
        # Metadata
        f.write("/**\n")
        
        # Query name
        query_name = query['query_id'].replace('_', ' ').title()
        f.write(f" * @name {query_name}\n")
        
        # Description
        f.write(f" * @description {query['message']}\n")
        
        # Query type
        f.write(" * @kind problem\n")
        
        # Severity
        f.write(f" * @problem.severity {query['severity']}\n")
        
        # Precision
        f.write(f" * @precision {query['precision']}\n")
        
        # ID
        f.write(f" * @id cpp/{query['query_id']}\n")
        
        # Tags
        f.write(" * @tags security\n")
        if query.get('cwe_name'):
            cwe_number = extract_cwe_number(query['cwe_name'])
            if cwe_number:
                f.write(f" *       external/cwe/cwe-{cwe_number}\n")
        
        f.write(" */\n\n")
        
        # Imports (base import, may be extended)
        f.write("import cpp\n")
        
        # Query body based on type
        query_type = query.get('query_type')
        
        if query_type == 'dangerous_function':
            write_dangerous_function_query(f, query)
        elif query_type in ['missing_cleanup', 'missing_free', 'missing_password_cleanup']:
            write_missing_cleanup_query(f, query)
        elif query_type in ['stack_sensitive_data', 'password_not_cleared', 'unchecked_return']:
            write_specific_vulnerability_query(f, query)
        else:
            # Fallback
            f.write("\nfrom Expr expr\n")
            f.write("where any()\n")
            f.write(f"select expr, \"{query['message']}\"\n")


def extract_cwe_number(cwe_name: str) -> Optional[str]:
    """Extract CWE number from name like 'CWE-120'."""
    match = re.search(r'CWE-?(\d+)', cwe_name, re.IGNORECASE)
    return match.group(1) if match else None


def emit_codeql_queries(queries: List[Dict], output_dir: str):
    """Output all CodeQL queries to individual .ql files."""
    os.makedirs(output_dir, exist_ok=True)
    
    for query in queries:
        filename = f"{query['query_id']}.ql"
        filepath = os.path.join(output_dir, filename)
        emit_codeql_query_file(query, filepath)
        print(f"Generated: {filepath}", file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_improved_codeql.py <analysis_json_file> [cwe_name] [output_dir]")
        print("  Where analysis_json_file is the output from find_common_patterns.py")
        sys.exit(1)

    analysis_file = sys.argv[1]
    cwe_name = sys.argv[2] if len(sys.argv) > 2 else ""
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "improved_codeql_queries"

    # Load analysis
    analysis = load_analysis(analysis_file)

    # Extract patterns
    patterns = extract_meaningful_patterns(analysis)

    queries = []

    # Generate queries for dangerous functions
    for pattern in patterns:
        if pattern['type'] == 'dangerous_functions':
            for i, func in enumerate(pattern['functions']):
                query_id = f"{cwe_name.lower().replace(' ', '_')}_dangerous_func_{i+1}"
                query = generate_dangerous_function_query(func, cwe_name, query_id)
                queries.append(query)

    # Generate queries for missing cleanup
    cleanup_queries = generate_missing_cleanup_queries(analysis, cwe_name)
    queries.extend(cleanup_queries)

    # Generate CWE-specific queries
    specific_queries = generate_specific_vulnerability_queries(cwe_name, analysis)
    queries.extend(specific_queries)

    if not queries:
        print("# No queries generated", file=sys.stderr)
        return

    # Output queries
    print(f"# Generated {len(queries)} improved CodeQL queries for {cwe_name}", file=sys.stderr)
    print(f"# Based on analysis of {analysis.get('num_files', 0)} files", file=sys.stderr)
    print("", file=sys.stderr)

    emit_codeql_queries(queries, output_dir)
    
    print(f"\nAll queries written to {output_dir}/", file=sys.stderr)


if __name__ == "__main__":
    main()
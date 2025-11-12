import re
import os

def extract_function_pairs(c_file_path):
    """
    Extract BAD and GOOD function pairs from a C file.
    Returns a list of tuples: [(bad_function, good_function), ...]
    """
    with open(c_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract the header section (includes, defines, etc.)
    header_match = re.search(r'^(.*?)(?=// BAD)', content, re.DOTALL)
    header = header_match.group(1).strip() if header_match else ""
    
    # Find all BAD functions
    bad_pattern = r'// BAD.*?^}' 
    bad_funcs = re.findall(bad_pattern, content, re.DOTALL | re.MULTILINE)
    
    # Find all GOOD functions
    good_pattern = r'// GOOD.*?^}'
    good_funcs = re.findall(good_pattern, content, re.DOTALL | re.MULTILINE)
    
    # Pair them up
    pairs = list(zip(bad_funcs, good_funcs))
    
    return header, pairs

def create_split_files(c_file_path, output_dir='split_files'):
    """
    Split the C file into multiple files, each with one BAD and one GOOD function.
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract header and function pairs
    header, pairs = extract_function_pairs(c_file_path)
    
    # Get base filename
    base_name = os.path.splitext(os.path.basename(c_file_path))[0]
    
    # Create a file for each pair
    for idx, (bad_func, good_func) in enumerate(pairs, 1):
        output_filename = f"{base_name}_part{idx}.c"
        output_path = os.path.join(output_dir, output_filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            # Write header
            f.write(header)
            f.write('\n\n')
            
            # Write BAD function
            f.write(bad_func)
            f.write('\n\n')
            
            # Write GOOD function
            f.write(good_func)
            f.write('\n')
        
        print(f"Created: {output_path}")
    
    print(f"\nTotal files created: {len(pairs)}")
    return len(pairs)

# Main execution
if __name__ == "__main__":
    dir = "gpt-generated/"
    input_file = dir + "CWE364_gpt_generated.c"
    output_directory = dir + "CWE364_Signal_Handler_Race_Condition"
    
    num_files = create_split_files(input_file, output_directory)
    print(f"\nSuccessfully split into {num_files} files in '{output_directory}/' directory")
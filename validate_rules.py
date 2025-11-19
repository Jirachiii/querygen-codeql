#!/usr/bin/env python3
"""
Validate generated Semgrep rules by running them on the source CWE files
and measuring detection accuracy.

This script:
1. Runs each generated rule file on its corresponding CWE directory
2. Analyzes which functions are detected (bad vs good)
3. Calculates accuracy metrics
"""

import sys
import os
import json
import subprocess
import glob
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict


def find_rule_files(dir: str) -> List[Tuple[str, str]]:
    """
    Find all generated rule files and their corresponding CWE directories.
    Returns list of (rule_file, cwe_dir) tuples.
    """
    output_path = Path(dir)
    rule_files = list(output_path.glob("*.yaml"))

    pairs = []
    for rule_file in rule_files:
        # Extract CWE name from rule file name
        # e.g., cwe226_sensitive_information_uncleared_before_release_rules.yaml
        cwe_name = rule_file.stem.split("__")[0]

        pairs.append((str(rule_file), str(cwe_name)))

        # Find matching CWE directory
        # Look for CWE directory that matches
        # cwe_dirs = Path("CWEs").glob("CWE*")
        # for cwe_dir in cwe_dirs:
        #     cwe_normalized = cwe_dir.name.lower().replace("cwe", "").replace("_", " ")
        #     rule_normalized = cwe_name.replace("cwe", "").replace("_", " ")

        #     if cwe_normalized.startswith(rule_normalized.split()[0]):
        #         pairs.append((str(rule_file), str(cwe_dir)))
        #         break

    return pairs


def extract_function_labels_from_file(file_path: str) -> Dict[str, List[str]]:
    """
    Extract function names and their labels (bad/good) from a C file.

    Returns:
        {"bad": [list of bad function names],
         "good": [list of good function names]}
    """
    functions = {"bad": [], "good": [], "other": []}

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Find function definitions
        # Pattern: return_type function_name(params)
        func_pattern = r'\b(?:void|int|char|static\s+void|static\s+int)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{'

        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)

            # Classify based on name
            if 'bad' in func_name.lower():
                functions["bad"].append(func_name)
            elif 'good' in func_name.lower() or func_name.lower().startswith('good'):
                functions["good"].append(func_name)
            else:
                functions["other"].append(func_name)

    except Exception as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)

    return functions


def run_semgrep(rule_file: str, target_dir: str) -> Dict:
    """
    Run Semgrep with the given rule file on target directory.
    Returns Semgrep output as JSON.
    """
    files = glob.glob(target_dir)
    cmd = [
        "semgrep",
        "--config", rule_file,
        *files,
        "--json",
        "--quiet"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0 or result.returncode == 1:  # 0 = no findings, 1 = findings
            return json.loads(result.stdout)
        else:
            print(result)
            print(f"Semgrep error: {result.stderr}", file=sys.stderr)
            return {"results": []}

    except subprocess.TimeoutExpired:
        print(f"Timeout running Semgrep on {target_dir}", file=sys.stderr)
        return {"results": []}
    except json.JSONDecodeError as e:
        print(f"Error parsing Semgrep output: {e}", file=sys.stderr)
        return {"results": []}
    except FileNotFoundError:
        print("Error: Semgrep not found. Install with: pip install semgrep", file=sys.stderr)
        return {"results": []}


def analyze_semgrep_results(semgrep_output: Dict, cwe_dir: str) -> Dict:
    """
    Analyze Semgrep results to determine which functions were detected.

    Returns:
        {
            "detected_bad": [list of bad testfiles detected],
            "detected_good": [list of good testfiles detected],
            "detected_other": [list of other functions detected],
            "total_findings": count,
            "files_with_findings": [list of files]
        }
    """
    detected = {
        "detected_bad": set(),
        "detected_good": set(),
        "detected_other": set(),
        "files_with_findings": set()
    }

    results = semgrep_output.get("results", [])

    for result in results:
        file_path = result.get("path", "")
        detected["files_with_findings"].add(file_path)
        if file_path.endswith('_bad.c'):
            detected["detected_bad"].add(file_path)
        elif file_path.endswith('_good.c'):
            detected["detected_good"].add(file_path)
        else:
            detected["detected_other"].add(file_path)

    return {
        "detected_bad": list(detected["detected_bad"]),
        "detected_good": list(detected["detected_good"]),
        "detected_other": list(detected["detected_other"]),
        "total_findings": len(results),
        "files_with_findings": list(detected["files_with_findings"])
    }


# def calculate_metrics(all_functions: Dict, detected: Dict) -> Dict:
#     """
#     Calculate detection metrics.

#     Metrics:
#     - True Positives (TP): bad testfiles detected
#     - False Negatives (FN): bad testfiles NOT detected
#     - False Positives (FP): good testfiles detected
#     - True Negatives (TN): good testfiles NOT detected
#     - Precision: TP / (TP + FP)
#     - Recall: TP / (TP + FN)
#     - F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
#     """
#     # For file
#     all_bad = 2
#     all_good = 2

#     detected_bad = set(detected["detected_bad"])
#     detected_good = set(detected["detected_good"])

#     # Calculate metrics
#     tp = len(detected_bad)  # bad testfiles correctly detected
#     fn = len(all_bad - detected_bad)  # bad testfiles missed
#     fp = len(detected_good)  # good testfiles incorrectly flagged
#     tn = len(all_good - detected_good)  # good testfiles correctly not flagged

#     # Precision: of all detections, how many were actually bad?
#     precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

#     # Recall: of all bad testfiles, how many did we detect?
#     recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

#     # F1 Score: harmonic mean of precision and recall
#     f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

#     # Accuracy: correct predictions / total predictions
#     accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

#     return {
#         "true_positives": tp,
#         "false_negatives": fn,
#         "false_positives": fp,
#         "true_negatives": tn,
#         "precision": precision,
#         "recall": recall,
#         "f1_score": f1,
#         "accuracy": accuracy,
#         "total_bad_functions": len(all_bad),
#         "total_good_functions": len(all_good),
#         "detected_bad_functions": list(detected_bad),
#         "missed_bad_functions": list(all_bad - detected_bad),
#         "incorrectly_flagged_good_functions": list(detected_good)
#     }


def validate_cwe(rule_file: str, cwe_name: str, dir: str) -> Dict:
    """
    Validate rules for a single CWE.
    """
    print(f"\n{'='*60}")
    print(f"Validating: {os.path.basename(rule_file)}")
    print(f"CWE Name: {cwe_name}")
    print(f"{'='*60}\n")

    print(f"Testfiles found:")
    print(f"  - Bad testfiles: 2")
    print(f"  - Good testfiles: 2")

    # Run Semgrep
    print(f"\nRunning Semgrep...")
    target_dir = str(dir) + f"/{cwe_name}*.c"
    semgrep_output = run_semgrep(rule_file, target_dir)

    # Analyze results
    detected = analyze_semgrep_results(semgrep_output, cwe_name)

    print(f"\nSemgrep Results:")
    print(f"  - Total findings: {detected['total_findings']}")
    print(f"  - Files with findings: {len(detected['files_with_findings'])}")
    print(f"  - Bad testfiles detected: {len(detected['detected_bad'])}")
    print(f"  - Good testfiles detected: {len(detected['detected_good'])}")

    return {
        "rule_file": rule_file,
        "cwe_dir": dir,
        "detected": detected,
    }


# def generate_report(all_results: List[Dict], output_file: str):
#     """
#     Generate a comprehensive validation report.
#     """
#     report = {
#         "summary": {
#             "total_cwes": len(all_results),
#             "avg_precision": 0.0,
#             "avg_recall": 0.0,
#             "avg_f1": 0.0,
#             "avg_accuracy": 0.0
#         },
#         "per_cwe_results": []
#     }

#     total_precision = 0.0
#     total_recall = 0.0
#     total_f1 = 0.0
#     total_accuracy = 0.0

#     for result in all_results:
#         metrics = result["metrics"]

#         total_precision += metrics["precision"]
#         total_recall += metrics["recall"]
#         total_f1 += metrics["f1_score"]
#         total_accuracy += metrics["accuracy"]

#         report["per_cwe_results"].append({
#             "cwe": os.path.basename(result["cwe_dir"]),
#             "rule_file": os.path.basename(result["rule_file"]),
#             "metrics": metrics,
#             "total_bad_functions": metrics["total_bad_functions"],
#             "total_good_functions": metrics["total_good_functions"],
#             "detected_bad": len(result["detected"]["detected_bad"]),
#             "detected_good": len(result["detected"]["detected_good"])
#         })

#     n = len(all_results)
#     if n > 0:
#         report["summary"]["avg_precision"] = total_precision / n
#         report["summary"]["avg_recall"] = total_recall / n
#         report["summary"]["avg_f1"] = total_f1 / n
#         report["summary"]["avg_accuracy"] = total_accuracy / n

#     # Save report
#     with open(output_file, 'w') as f:
#         json.dump(report, f, indent=2)

#     print(f"\n{'='*60}")
#     print("OVERALL SUMMARY")
#     print(f"{'='*60}")
#     print(f"Total CWEs validated: {n}")
#     print(f"Average Precision: {report['summary']['avg_precision']:.2%}")
#     print(f"Average Recall: {report['summary']['avg_recall']:.2%}")
#     print(f"Average F1 Score: {report['summary']['avg_f1']:.2%}")
#     print(f"Average Accuracy: {report['summary']['avg_accuracy']:.2%}")
#     print(f"\nDetailed report saved to: {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_rules.py <directory>")
        print("Example: python3 validate_rules.py output/")
        sys.exit(1)

    dir = sys.argv[1]

    if not os.path.isdir(dir):
        print(f"Error: {dir} is not a valid directory", file=sys.stderr)
        sys.exit(1)

    # Find all rule files and their corresponding CWE directories
    pairs = find_rule_files(dir)

    if not pairs:
        print(f"No rule files found in {dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(pairs)} CWEs to validate")

    # Validate each CWE
    all_results = []
    all_findings = 0
    all_files_with_findings = set()
    all_tp = set()
    all_fp = set()

    for rule_file, cwe_name in pairs:
        try:
            result = validate_cwe(rule_file, cwe_name, dir)
            all_results.append(result)
            all_findings += result['detected'].get('total_findings', 0)
            all_files_with_findings.update(result['detected']['files_with_findings'])
            all_tp.update(result['detected']['detected_bad'])
            all_fp.update(result['detected']['detected_good'])
        except Exception as e:
            print(f"Error validating {rule_file}: {e}", file=sys.stderr)
            continue

    print(f"\n{'='*60}")
    print("== OVERALL SUMMARY ==")
    print("- Total findings:", all_findings)
    print("- Total files scanned:", len(pairs)*2)
    print("- Files with findings:", len(all_files_with_findings))
    print("- True Positive:", len(all_tp))
    print("- False Positive:", len(all_fp))
    # Generate report
    # report_file = os.path.join(dir, "validation_report.json")
    # generate_report(all_results, report_file)


if __name__ == "__main__":
    main()
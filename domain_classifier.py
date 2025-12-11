#!/usr/bin/env python3
"""
Domain Classification Tool for SPF/DMARC Analysis
==================================================

This script classifies domains from analysis results based on SPF and DMARC
configurations to identify interesting test cases for manual email spoofing tests.

Features:
- Classify domains by SPF result and DMARC policy combinations
- Additional classification by PTR, includes, and DNS lookup counts
- Export classified domain lists for targeted testing
- Interactive filtering and selection
- Statistical overview of configuration patterns

Author: Security Analysis Team
Date: December 2025
"""

import csv
import argparse
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import json


# ============================================================================
# CLASSIFICATION CATEGORIES
# ============================================================================

# Main classification keys
PRIMARY_KEYS = ['spf_check_result_flag', 'dmarc_policy']

# Additional optional classification keys
ADDITIONAL_KEYS = [
    'has_ptr',
    'has_include',
    'dns_lookup_count',
    'unregistered_domain_in_include'
]

# DNS lookup count ranges for classification
LOOKUP_COUNT_RANGES = [
    (0, 0, 'no_lookups'),
    (1, 5, 'low_lookups'),
    (6, 10, 'normal_lookups'),
    (11, float('inf'), 'high_lookups')
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def normalize_value(value: str) -> str:
    """Normalize empty/None values for consistent classification"""
    if not value or value.strip() == '' or value.lower() == 'none':
        return 'none'
    return value.strip().lower()


def classify_dns_lookups(count_str: str) -> str:
    """Classify DNS lookup count into ranges"""
    try:
        count = int(count_str)
        for min_val, max_val, label in LOOKUP_COUNT_RANGES:
            if min_val <= count <= max_val:
                return label
    except (ValueError, TypeError):
        pass
    return 'unknown'


def get_classification_key(row: Dict[str, str], keys: List[str]) -> Tuple[str, ...]:
    """
    Generate classification key from row data.

    Args:
        row: CSV row dictionary
        keys: List of column names to use for classification

    Returns:
        Tuple of normalized values for classification
    """
    key_values = []

    for key in keys:
        value = row.get(key, '')

        # Special handling for DNS lookup count
        if key == 'dns_lookup_count':
            value = classify_dns_lookups(value)
        else:
            value = normalize_value(value)

        key_values.append(value)

    return tuple(key_values)


# ============================================================================
# CLASSIFICATION ENGINE
# ============================================================================

def classify_domains(input_csv: str, classification_keys: List[str]) -> Tuple[Dict[Tuple, List[Dict]], str]:
    """
    Classify domains based on specified keys.

    Args:
        input_csv: Path to analysis results CSV
        classification_keys: List of column names for classification

    Returns:
        Tuple of (Dictionary mapping classification tuples to lists of domain records, from_ip string)
    """
    if not os.path.exists(input_csv):
        print(f"Error: Input file not found: {input_csv}")
        sys.exit(1)

    classifications = defaultdict(list)
    total_domains = 0
    from_ip = "unknown"

    try:
        with open(input_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            # Validate that required keys exist
            if reader.fieldnames:
                missing_keys = [
                    k for k in classification_keys if k not in reader.fieldnames]
                if missing_keys:
                    print(f"Error: Missing columns in CSV: {missing_keys}")
                    sys.exit(1)

            for row in reader:
                total_domains += 1
                # Extract from_ip from first row
                if total_domains == 1 and 'from_ip' in row:
                    from_ip = row.get(
                        'from_ip', 'unknown').strip().replace('.', '-')
                key = get_classification_key(row, classification_keys)
                classifications[key].append(row)

    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    print(f"\n✓ Processed {total_domains} domains")
    print(f"✓ Found {len(classifications)} unique classification groups")
    print(f"✓ From IP: {from_ip}")

    return classifications, from_ip


# ============================================================================
# REPORTING AND EXPORT
# ============================================================================

def print_classification_summary(classifications: Dict[Tuple, List[Dict]],
                                 classification_keys: List[str]):
    """
    Print statistical summary of classifications.

    Args:
        classifications: Dictionary of classification results
        classification_keys: Keys used for classification
    """
    print("\n" + "=" * 80)
    print("CLASSIFICATION SUMMARY")
    print("=" * 80)
    print(f"\nClassification Keys: {' | '.join(classification_keys)}")
    print(f"\nTotal Classification Groups: {len(classifications)}")
    print("\n" + "-" * 80)

    # Sort by count (descending)
    sorted_classifications = sorted(
        classifications.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

    print(f"{'Group':<6} {'Count':<8} {' | '.join(f'{k:<20}' for k in classification_keys)}")
    print("-" * 80)

    for idx, (key, domains) in enumerate(sorted_classifications, 1):
        count = len(domains)
        key_str = ' | '.join(f'{v:<20}' for v in key)
        print(f"{idx:<6} {count:<8} {key_str}")

    print("=" * 80)


def export_classification_group(domains: List[Dict], output_file: str,
                                classification_label: str):
    """
    Export a specific classification group to CSV.

    Args:
        domains: List of domain records
        output_file: Output CSV file path
        classification_label: Human-readable label for the group
    """
    if not domains:
        print(f"Warning: No domains to export for {classification_label}")
        return

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=domains[0].keys())
            writer.writeheader()
            writer.writerows(domains)

        print(f"✓ Exported {len(domains)} domains to: {output_file}")

    except Exception as e:
        print(f"Error exporting to {output_file}: {e}")


def export_all_classifications(classifications: Dict[Tuple, List[Dict]],
                               classification_keys: List[str],
                               output_dir: str):
    """
    Export all classification groups to separate CSV files.

    Args:
        classifications: Dictionary of classification results
        classification_keys: Keys used for classification
        output_dir: Directory to save output files
    """
    os.makedirs(output_dir, exist_ok=True)

    print(f"\nExporting all classification groups to: {output_dir}")
    print("-" * 80)

    for key, domains in classifications.items():
        # Create filename from classification key
        filename_parts = []
        for k, v in zip(classification_keys, key):
            # Shorten key names for filename
            short_key = k.replace('_flag', '').replace(
                'dmarc_', '').replace('spf_check_result', 'spf')
            filename_parts.append(f"{short_key}={v}")

        filename = "_".join(filename_parts) + ".csv"
        # Sanitize filename
        filename = filename.replace('/', '-').replace('\\', '-')

        output_path = os.path.join(output_dir, filename)
        export_classification_group(domains, output_path, str(key))

    print("-" * 80)
    print(f"✓ Exported {len(classifications)} classification groups")


def export_domain_list(domains: List[Dict], output_file: str):
    """
    Export just domain names (one per line) for easy testing.

    Args:
        domains: List of domain records
        output_file: Output text file path
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for domain_record in domains:
                domain = domain_record.get('Domain_to_be_spoofed', '').strip()
                if domain:
                    f.write(domain + '\n')

        print(f"✓ Exported {len(domains)} domain names to: {output_file}")

    except Exception as e:
        print(f"Error exporting domain list: {e}")


def export_json_summary(classifications: Dict[Tuple, List[Dict]],
                        classification_keys: List[str],
                        output_file: str):
    """
    Export classification summary as JSON.

    Args:
        classifications: Dictionary of classification results
        classification_keys: Keys used for classification
        output_file: Output JSON file path
    """
    summary = {
        'classification_keys': classification_keys,
        'total_groups': len(classifications),
        'groups': []
    }

    for key, domains in classifications.items():
        group_data = {
            'classification': dict(zip(classification_keys, key)),
            'count': len(domains),
            'sample_domains': [d.get('Domain_to_be_spoofed', '') for d in domains[:5]]
        }
        summary['groups'].append(group_data)

    # Sort by count
    summary['groups'].sort(key=lambda x: x['count'], reverse=True)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        print(f"✓ Exported JSON summary to: {output_file}")

    except Exception as e:
        print(f"Error exporting JSON: {e}")


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_filter(classifications: Dict[Tuple, List[Dict]],
                       classification_keys: List[str], from_ip: str = 'unknown'):
    """
    Interactive mode to filter and export specific classification groups.

    Args:
        classifications: Dictionary of classification results
        classification_keys: Keys used for classification
        from_ip: IP address from CSV (for directory naming)
    """
    print("\n" + "=" * 80)
    print("INTERACTIVE FILTER MODE")
    print("=" * 80)

    # Sort by count
    sorted_classifications = sorted(
        classifications.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

    print(f"\nAvailable groups:\n")
    print(f"{'#':<4} {'Count':<8} {' | '.join(classification_keys)}")
    print("-" * 80)

    for idx, (key, domains) in enumerate(sorted_classifications, 1):
        key_str = ' | '.join(str(v) for v in key)
        print(f"{idx:<4} {len(domains):<8} {key_str}")

    print("\nEnter group number to export (or 'q' to quit, 'all' to export all): ", end='')

    try:
        choice = input().strip().lower()

        if choice == 'q':
            return

        if choice == 'all':
            default_dir = os.path.join(
                'output', f'domain-categories-{from_ip}')
            output_dir = input(
                f"Enter output directory name (default: '{default_dir}'): ").strip()
            if not output_dir:
                output_dir = default_dir
            os.makedirs(output_dir, exist_ok=True)
            export_all_classifications(
                classifications, classification_keys, output_dir)
            return

        # Single group selection
        group_num = int(choice)
        if 1 <= group_num <= len(sorted_classifications):
            key, domains = sorted_classifications[group_num - 1]

            print(f"\nSelected group: {dict(zip(classification_keys, key))}")
            print(f"Domains in group: {len(domains)}")

            output_file = input(
                "Enter output filename (e.g., 'selected_domains.csv'): ").strip()
            if output_file:
                export_classification_group(domains, output_file, str(key))

                # Ask if domain list is also needed
                domain_list = input(
                    "Also export domain names only? (y/n): ").strip().lower()
                if domain_list == 'y':
                    txt_file = output_file.replace('.csv', '.txt')
                    export_domain_list(domains, txt_file)
        else:
            print("Invalid group number")

    except ValueError:
        print("Invalid input")
    except KeyboardInterrupt:
        print("\n\nInterrupted")


# ============================================================================
# MAIN CLI
# ============================================================================

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Classify domains by SPF/DMARC configuration for manual testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic classification by SPF result and DMARC policy
  %(prog)s -i results.csv --summary
  
  # Add PTR and include classifications
  %(prog)s -i results.csv --keys spf_check_result_flag dmarc_policy has_ptr has_include
  
  # Export all groups to separate files
  %(prog)s -i results.csv --export-all -o classified_domains/
  
  # Export specific combination
  %(prog)s -i results.csv --filter spf_check_result_flag=fail dmarc_policy=none -o fail_none.csv
  
  # Interactive mode
  %(prog)s -i results.csv --interactive
  
  # Export JSON summary
  %(prog)s -i results.csv --json summary.json
        """
    )

    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input CSV file from domain_analyzer.py'
    )

    parser.add_argument(
        '--keys', '-k',
        nargs='+',
        default=['spf_check_result_flag', 'dmarc_policy'],
        help='Classification keys (default: spf_check_result_flag dmarc_policy)'
    )

    parser.add_argument(
        '--summary', '-s',
        action='store_true',
        help='Print classification summary'
    )

    parser.add_argument(
        '--export-all',
        action='store_true',
        help='Export all classification groups to separate CSV files'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file or directory (for --export-all)'
    )

    parser.add_argument(
        '--filter',
        nargs='+',
        help='Filter by key=value pairs (e.g., spf_check_result_flag=fail dmarc_policy=none)'
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Interactive mode to select and export groups'
    )

    parser.add_argument(
        '--json',
        help='Export classification summary as JSON'
    )

    parser.add_argument(
        '--domain-list',
        action='store_true',
        help='Export domain names only (one per line)'
    )

    args = parser.parse_args()

    # Perform classification
    print(f"Classifying domains from: {args.input}")
    print(f"Using keys: {', '.join(args.keys)}")

    classifications, from_ip = classify_domains(args.input, args.keys)

    # Summary mode (default if nothing else specified)
    if args.summary or not (args.export_all or args.filter or args.interactive or args.json):
        print_classification_summary(classifications, args.keys)

    # Export all groups
    if args.export_all:
        if args.output:
            output_dir = args.output
        else:
            output_dir = os.path.join('output', f'domain-categories-{from_ip}')

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        export_all_classifications(classifications, args.keys, output_dir)

    # Filter and export specific group
    if args.filter:
        filter_dict = {}
        for f in args.filter:
            if '=' in f:
                key, value = f.split('=', 1)
                filter_dict[key] = normalize_value(value)

        # Find matching classification
        filter_key = tuple(filter_dict.get(k, '') for k in args.keys)

        if filter_key in classifications:
            domains = classifications[filter_key]
            print(
                f"\nFound {len(domains)} domains matching filter: {filter_dict}")

            if args.output:
                export_classification_group(
                    domains, args.output, str(filter_dict))

                if args.domain_list:
                    txt_file = args.output.replace('.csv', '.txt')
                    export_domain_list(domains, txt_file)
            else:
                print("Specify --output to export this group")
        else:
            print(f"No domains found matching filter: {filter_dict}")
            print("Available combinations:")
            print_classification_summary(classifications, args.keys)

    # JSON export
    if args.json:
        export_json_summary(classifications, args.keys, args.json)

    # Interactive mode
    if args.interactive:
        interactive_filter(classifications, args.keys, from_ip)


if __name__ == '__main__':
    main()

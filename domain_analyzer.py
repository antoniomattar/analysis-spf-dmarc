#!/usr/bin/env python3
"""
Domain Analysis Pipeline for SPF/DMARC Security Assessment
============================================================

This script performs comprehensive DNS-based analysis of domains to assess
their email authentication configurations and spoofing vulnerability.

Features:
- SPF record retrieval and parsing with include chain expansion
- DMARC record retrieval and policy extraction
- SPF evaluation simulation from attacker IP
- Multi-SMTP receiver testing framework
- Resume support for interrupted scans
- Robust error handling with exponential backoff

Author: Security Analysis Team
Date: December 2025
"""

import csv
import dns.resolver
import dns.exception
import spf
import socket
import argparse
import os
import logging
import sys
from time import sleep
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


# ============================================================================
# CONFIGURATION
# ============================================================================

# DNS resolution configuration
DNS_TIMEOUT = 5.0
MAX_DNS_RETRIES = 3
RETRY_BACKOFF_BASE = 2
MAX_INCLUDE_DEPTH = 10

# CSV field names
CSV_FIELDNAMES = [
    "Domain_to_be_spoofed",
    "its_spf_record",
    "has_ptr",
    "has_include",
    "dns_lookup_count",
    "unregistered_domain_in_include",
    "its_dmarc_record",
    "dmarc_policy",
    "dmarc_rua",
    "dmarc_ruf",
    "from_ip",
    "spf_check_result_flag",
    "what_happened"
]


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SPFRecord:
    """Represents parsed SPF record data"""
    raw_record: str
    has_ptr: bool
    has_include: bool
    includes: List[str]
    dns_lookup_count: int
    unregistered_includes: List[str]
    redirect: Optional[str]
    exp: Optional[str]
    all_qualifier: str  # +, -, ~, ?


@dataclass
class DMARCRecord:
    """Represents parsed DMARC record data"""
    raw_record: str
    policy: str  # p= value
    subdomain_policy: Optional[str]  # sp= value
    rua: Optional[str]
    ruf: Optional[str]
    pct: Optional[str]
    adkim: Optional[str]
    aspf: Optional[str]


@dataclass
class DomainAnalysis:
    """Complete analysis result for a domain"""
    domain: str
    spf_record: Optional[SPFRecord]
    dmarc_record: Optional[DMARCRecord]
    spf_result: str  # pass, fail, softfail, neutral, permerror, temperror, none
    from_ip: str


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(log_level=logging.INFO):
    """Configure logging with timestamp and level"""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


# ============================================================================
# DNS UTILITY FUNCTIONS
# ============================================================================

def dns_query_with_retry(domain: str, record_type: str = 'TXT',
                         max_retries: int = MAX_DNS_RETRIES) -> Optional[List[str]]:
    """
    Query DNS with exponential backoff retry logic.

    Args:
        domain: Domain to query
        record_type: DNS record type (TXT, A, AAAA, etc.)
        max_retries: Maximum number of retry attempts

    Returns:
        List of record strings, or None on failure
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    for attempt in range(max_retries):
        try:
            answers = resolver.resolve(domain, record_type)
            if record_type == 'TXT':
                result = []
                for answer in answers:
                    # Handle TXT record strings properly
                    txt_parts = []
                    for txt_string in answer.strings:
                        if isinstance(txt_string, bytes):
                            txt_parts.append(txt_string.decode(
                                'utf-8', errors='ignore'))
                        else:
                            txt_parts.append(str(txt_string))
                    result.append(''.join(txt_parts))
                return result
            else:
                return [str(answer) for answer in answers]

        except dns.resolver.NXDOMAIN:
            logging.debug(f"NXDOMAIN: {domain}")
            return None

        except dns.resolver.NoAnswer:
            logging.debug(f"No {record_type} record: {domain}")
            return None

        except dns.resolver.Timeout:
            if attempt < max_retries - 1:
                wait_time = RETRY_BACKOFF_BASE ** attempt
                logging.warning(
                    f"DNS timeout for {domain}, retrying in {wait_time}s...")
                sleep(wait_time)
            else:
                logging.error(
                    f"DNS timeout for {domain} after {max_retries} attempts")
                return None

        except dns.exception.DNSException as e:
            logging.error(f"DNS error for {domain}: {e}")
            return None

        except Exception as e:
            logging.error(f"Unexpected error querying {domain}: {e}")
            return None

    return None


# ============================================================================
# SPF ANALYSIS FUNCTIONS
# ============================================================================

def get_spf_record(domain: str) -> Optional[str]:
    """
    Retrieve SPF record for a domain.

    Args:
        domain: Domain to query

    Returns:
        SPF record string, or None if not found
    """
    txt_records = dns_query_with_retry(domain, 'TXT')

    if not txt_records:
        return None

    # Find SPF record (starts with v=spf1)
    for record in txt_records:
        if record.strip().startswith('v=spf1'):
            return record.strip()

    return None


def parse_spf(spf_str: str, visited: Optional[Set[str]] = None, depth: int = 0) -> SPFRecord:
    """
    Parse SPF record and extract all relevant information.

    Args:
        spf_str: Raw SPF record string
        visited: Set of already visited domains (for cycle detection)
        depth: Current recursion depth

    Returns:
        SPFRecord object with parsed data
    """
    if visited is None:
        visited = set()

    has_ptr = False
    has_include = False
    includes = []
    unregistered_includes = []
    dns_lookup_count = 0
    redirect = None
    exp = None
    all_qualifier = '?'  # default neutral

    tokens = spf_str.split()

    for token in tokens:
        token = token.strip()

        # Track PTR mechanism (discouraged but still used)
        if 'ptr' in token.lower():
            has_ptr = True
            dns_lookup_count += 1

        # Extract include directives
        if token.startswith('include:'):
            has_include = True
            include_domain = token.split(':', 1)[1]
            includes.append(include_domain)
            dns_lookup_count += 1

            # Check if included domain exists
            if include_domain not in visited and depth < MAX_INCLUDE_DEPTH:
                visited.add(include_domain)
                if not dns_query_with_retry(include_domain, 'TXT'):
                    unregistered_includes.append(include_domain)
                else:
                    # Recursively count lookups in included SPF records
                    included_spf = get_spf_record(include_domain)
                    if included_spf:
                        included_parsed = parse_spf(
                            included_spf, visited, depth + 1)
                        dns_lookup_count += included_parsed.dns_lookup_count

        # Extract redirect
        elif token.startswith('redirect='):
            redirect = token.split('=', 1)[1]
            dns_lookup_count += 1

        # Extract exp (explanation)
        elif token.startswith('exp='):
            exp = token.split('=', 1)[1]
            dns_lookup_count += 1

        # Track mechanisms that cause DNS lookups
        elif any(token.startswith(prefix) for prefix in ['a:', 'a/', 'mx:', 'mx/', 'exists:']):
            dns_lookup_count += 1

        elif token.startswith('a') and len(token) == 1:
            dns_lookup_count += 1

        elif token.startswith('mx') and (len(token) == 2 or token[2] in ':/'):
            dns_lookup_count += 1

        # Extract all mechanism qualifier
        elif token.startswith(('-all', '~all', '+all', '?all')):
            all_qualifier = token[0]

    return SPFRecord(
        raw_record=spf_str,
        has_ptr=has_ptr,
        has_include=has_include,
        includes=includes,
        dns_lookup_count=dns_lookup_count,
        unregistered_includes=unregistered_includes,
        redirect=redirect,
        exp=exp,
        all_qualifier=all_qualifier
    )


def resolve_include_chain(domain: str, visited: Optional[Set[str]] = None,
                          depth: int = 0) -> Tuple[List[str], List[str]]:
    """
    Recursively resolve include chain and return all IPs and errors.

    Args:
        domain: Domain to resolve
        visited: Set of visited domains (cycle detection)
        depth: Current recursion depth

    Returns:
        Tuple of (resolved_ips, errors)
    """
    if visited is None:
        visited = set()

    if domain in visited or depth >= MAX_INCLUDE_DEPTH:
        return ([], [])

    visited.add(domain)
    resolved_ips = []
    errors = []

    # Get A/AAAA records
    for record_type in ['A', 'AAAA']:
        ips = dns_query_with_retry(domain, record_type)
        if ips:
            resolved_ips.extend(ips)

    # Get SPF and resolve includes
    spf_record = get_spf_record(domain)
    if spf_record:
        parsed = parse_spf(spf_record, set(), 0)
        for include_domain in parsed.includes:
            if include_domain not in visited:
                child_ips, child_errors = resolve_include_chain(
                    include_domain, visited, depth + 1
                )
                resolved_ips.extend(child_ips)
                errors.extend(child_errors)

    return (resolved_ips, errors)


def evaluate_spf(ip: str, mail_from: str, helo: str) -> str:
    """
    Evaluate SPF result for given parameters using pyspf library.

    Args:
        ip: Sender IP address
        mail_from: MAIL FROM address
        helo: HELO/EHLO hostname

    Returns:
        SPF result: pass, fail, softfail, neutral, permerror, temperror, none
    """
    try:
        result, explanation = spf.check2(i=ip, s=mail_from, h=helo)
        return result
    except Exception as e:
        logging.error(f"SPF evaluation error for {mail_from}: {e}")
        return "error"


# ============================================================================
# DMARC ANALYSIS FUNCTIONS
# ============================================================================

def get_dmarc_record(domain: str) -> Optional[str]:
    """
    Retrieve DMARC record for a domain.

    Args:
        domain: Domain to query

    Returns:
        DMARC record string, or None if not found
    """
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = dns_query_with_retry(dmarc_domain, 'TXT')

    if not txt_records:
        return None

    # Find DMARC record (starts with v=DMARC1)
    for record in txt_records:
        if record.strip().startswith('v=DMARC1'):
            return record.strip()

    return None


def parse_dmarc(dmarc_str: str) -> DMARCRecord:
    """
    Parse DMARC record and extract policy information.

    Args:
        dmarc_str: Raw DMARC record string

    Returns:
        DMARCRecord object with parsed data
    """
    policy = "none"
    subdomain_policy = None
    rua = None
    ruf = None
    pct = None
    adkim = None
    aspf = None

    # Split by semicolon and parse tags
    tags = [tag.strip() for tag in dmarc_str.split(';') if tag.strip()]

    for tag in tags:
        if '=' not in tag:
            continue

        key, value = tag.split('=', 1)
        key = key.strip().lower()
        value = value.strip()

        if key == 'p':
            policy = value
        elif key == 'sp':
            subdomain_policy = value
        elif key == 'rua':
            rua = value
        elif key == 'ruf':
            ruf = value
        elif key == 'pct':
            pct = value
        elif key == 'adkim':
            adkim = value
        elif key == 'aspf':
            aspf = value

    return DMARCRecord(
        raw_record=dmarc_str,
        policy=policy,
        subdomain_policy=subdomain_policy,
        rua=rua,
        ruf=ruf,
        pct=pct,
        adkim=adkim,
        aspf=aspf
    )


# ============================================================================
# DOMAIN ANALYSIS PIPELINE
# ============================================================================

def analyze_domain(domain: str, from_ip: str, helo: str) -> DomainAnalysis:
    """
    Perform complete analysis of a single domain.

    Args:
        domain: Domain to analyze
        from_ip: IP address to simulate sending from
        helo: HELO/EHLO hostname

    Returns:
        DomainAnalysis object with complete results
    """
    logging.info(f"Analyzing {domain}")

    # Retrieve and parse SPF
    spf_raw = get_spf_record(domain)
    spf_record = None
    if spf_raw:
        spf_record = parse_spf(spf_raw)
        logging.debug(
            f"  SPF: {spf_raw[:50]}... ({spf_record.dns_lookup_count} lookups)")
    else:
        logging.debug(f"  No SPF record found")

    # Retrieve and parse DMARC
    dmarc_raw = get_dmarc_record(domain)
    dmarc_record = None
    if dmarc_raw:
        dmarc_record = parse_dmarc(dmarc_raw)
        logging.debug(f"  DMARC: {dmarc_record.policy}")
    else:
        logging.debug(f"  No DMARC record found")

    # Evaluate SPF for the given IP
    mail_from = f"test@{domain}"
    spf_result = evaluate_spf(from_ip, mail_from, helo)
    logging.debug(f"  SPF Result: {spf_result}")

    return DomainAnalysis(
        domain=domain,
        spf_record=spf_record,
        dmarc_record=dmarc_record,
        spf_result=spf_result,
        from_ip=from_ip
    )


def analysis_to_csv_row(analysis: DomainAnalysis) -> Dict[str, str]:
    """
    Convert DomainAnalysis object to CSV row dictionary.

    Args:
        analysis: DomainAnalysis object

    Returns:
        Dictionary matching CSV_FIELDNAMES structure
    """
    spf = analysis.spf_record
    dmarc = analysis.dmarc_record

    return {
        "Domain_to_be_spoofed": analysis.domain,
        "its_spf_record": spf.raw_record if spf else "",
        "has_ptr": "True" if spf and spf.has_ptr else "False",
        "has_include": "True" if spf and spf.has_include else "False",
        "dns_lookup_count": str(spf.dns_lookup_count) if spf else "0",
        "unregistered_domain_in_include": ",".join(spf.unregistered_includes) if spf and spf.unregistered_includes else "None",
        "its_dmarc_record": dmarc.raw_record if dmarc else "",
        "dmarc_policy": dmarc.policy if dmarc else "",
        "dmarc_rua": dmarc.rua if dmarc and dmarc.rua else "None",
        "dmarc_ruf": dmarc.ruf if dmarc and dmarc.ruf else "None",
        "from_ip": analysis.from_ip,
        "spf_check_result_flag": analysis.spf_result,
        "what_happened": ""  # Left blank for manual entry
    }


# ============================================================================
# CSV PROCESSING AND RESUME SUPPORT
# ============================================================================

def load_processed_domains(output_csv: str) -> Set[str]:
    """
    Load already processed domains from output CSV.

    Args:
        output_csv: Path to output CSV file

    Returns:
        Set of domain strings
    """
    if not os.path.exists(output_csv):
        return set()

    processed = set()
    try:
        with open(output_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("Domain_to_be_spoofed", "").strip()
                if domain:
                    processed.add(domain)
    except Exception as e:
        logging.error(f"Error loading processed domains: {e}")

    return processed


def save_row(writer: csv.DictWriter, row: Dict[str, str], file_handle):
    """
    Save a single row to CSV and flush immediately for resume support.

    Args:
        writer: CSV DictWriter object
        row: Dictionary of row data
        file_handle: File handle to flush
    """
    writer.writerow(row)
    file_handle.flush()


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def run_analysis(input_csv: str, output_csv: str, from_ip: str, helo: str,
                 sleep_seconds: float = 0.0):
    """
    Main analysis pipeline: process domains from input CSV and generate output.

    Args:
        input_csv: Path to input CSV with 'domain' column
        output_csv: Path to output CSV
        from_ip: IP address to simulate sending from
        helo: HELO/EHLO hostname
        sleep_seconds: Optional delay between domain queries
    """
    # Load already processed domains
    processed = load_processed_domains(output_csv)
    logging.info(
        f"Loaded {len(processed)} already-processed domains")

    # Open output CSV in append mode
    file_exists = os.path.exists(output_csv)
    out_file = open(output_csv, 'a', newline='', encoding='utf-8')
    writer = csv.DictWriter(out_file, fieldnames=CSV_FIELDNAMES)

    # Write header if new file
    if not file_exists:
        writer.writeheader()
        out_file.flush()

    # Statistics
    total_domains = 0
    processed_count = 0
    skipped_count = 0
    error_count = 0

    try:
        with open(input_csv, 'r', newline='', encoding='utf-8') as in_file:
            reader = csv.DictReader(in_file)

            for row in reader:
                domain = row.get('domain', '').strip()
                if not domain:
                    continue

                total_domains += 1

                # Skip if already processed
                if domain in processed:
                    skipped_count += 1
                    continue

                try:
                    # Analyze domain
                    analysis = analyze_domain(domain, from_ip, helo)

                    # Convert to CSV row and save
                    csv_row = analysis_to_csv_row(analysis)
                    save_row(writer, csv_row, out_file)

                    processed_count += 1

                    # Log progress every 10 domains
                    if processed_count % 10 == 0:
                        logging.info(
                            f"Progress: {processed_count} domains processed, {skipped_count} skipped")

                    # Optional throttling
                    if sleep_seconds > 0:
                        sleep(sleep_seconds)

                except Exception as e:
                    logging.error(
                        f"Error processing {domain}: {e}")
                    error_count += 1

    finally:
        out_file.close()

    # Final statistics
    logging.info("=" * 60)
    logging.info("ANALYSIS COMPLETE")
    logging.info("=" * 60)
    logging.info(f"Total unique domains in input: {total_domains}")
    logging.info(f"New entries processed: {processed_count}")
    logging.info(f"Entries skipped (already done): {skipped_count}")
    logging.info(f"Errors encountered: {error_count}")
    logging.info(f"Output saved to: {output_csv}")
    logging.info("=" * 60)


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Comprehensive domain SPF/DMARC analysis pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input top1m.csv --output results.csv --from-ip 12.34.56.78 --helo scanner.test
  %(prog)s -i domains.csv -o output.csv --from-ip 1.2.3.4 --helo test.local --sleep 0.5
        """
    )

    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input CSV file with "domain" column'
    )

    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output CSV file for results'
    )

    parser.add_argument(
        '--from-ip',
        required=True,
        help='IP address to simulate sending from (attacker IP)'
    )

    parser.add_argument(
        '--helo',
        required=True,
        help='HELO/EHLO hostname to use in SPF checks'
    )

    parser.add_argument(
        '--sleep',
        type=float,
        default=0.0,
        help='Sleep interval between domain queries (seconds, default: 0)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose debug logging'
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    # Validate input file
    if not os.path.exists(args.input):
        logging.error(f"Input file not found: {args.input}")
        sys.exit(1)

    # Ensure output directory exists and prepend output/ if no directory specified
    output_path = args.output
    if os.path.dirname(output_path) == '':
        # No directory specified, use output/
        output_path = os.path.join('output', output_path)

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Run analysis
    logging.info("Starting domain analysis pipeline")
    logging.info(f"Input: {args.input}")
    logging.info(f"Output: {output_path}")
    logging.info(f"From IP: {args.from_ip}")
    logging.info(f"HELO: {args.helo}")

    run_analysis(
        input_csv=args.input,
        output_csv=output_path,
        from_ip=args.from_ip,
        helo=args.helo,
        sleep_seconds=args.sleep
    )


if __name__ == '__main__':
    main()

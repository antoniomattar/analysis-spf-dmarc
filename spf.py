"""
spf_check.py

Requirements:
    pip install dnspython

Usage:
    python spf_check.py input.csv output.csv

Input CSV: one domain per line (no header required)
Output CSV: domain,category,raw_spf (raw_spf may be empty),error (if any)
"""

import csv
import sys
import time
import argparse
from collections import defaultdict

import dns.resolver
import dns.exception

# --- Helper functions -----------------------------------------------------


def normalize_txt_rdata(rdata):
    """
    Convert a dns.rdata (TXT) to a single Python string.
    rdata.strings is a sequence of bytes (in dnspython).
    """
    try:
        # rdata.strings can be multiple byte chunks that together form the TXT
        chunks = []
        for part in rdata.strings:
            # part may be bytes on py3
            if isinstance(part, bytes):
                chunks.append(part)
            else:
                # already str (rare), encode to utf-8 bytes then decode later
                chunks.append(str(part).encode("utf-8"))
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:
        # Fallback to rdata.to_text() then strip surrounding quotes
        txt = rdata.to_text()
        if txt.startswith('"') and txt.endswith('"'):
            return txt[1:-1]
        return txt


def find_spf_txt_from_txt_records(txt_records):
    """
    Given a list of TXT rdata objects, return the first string that starts with v=spf1
    """
    for rdata in txt_records:
        txt = normalize_txt_rdata(rdata).strip()
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def classify_spf(txt):
    """
    Very simple heuristic classifier:
      - 'secure' -> contains '-all'
      - 'neutral' -> contains '~all' or '?all'
      - 'missing_or_vulnerable' -> no 'all' mechanism or no spf at all
    Returns category string.
    """
    if not txt:
        return "no_spf"
    txt_l = txt.lower()
    if "-all" in txt_l:
        return "secure"
    if "~all" in txt_l or "?all" in txt_l:
        return "neutral"
    # no explicit all -> vulnerable / ambiguous (could rely on include chains)
    return "vulnerable"

# --- Main checking routine -----------------------------------------------


def check_spf_for_domain(domain, resolver, timeout=5.0):
    """
    Query TXT records for domain and return tuple (category, spf_text, error_message)
    category is one of: secure, neutral, vulnerable, no_spf, error
    """
    try:
        answers = resolver.resolve(domain, "TXT", lifetime=timeout)
        # answers is an iterable of rdata objects
        spf_text = find_spf_txt_from_txt_records(answers)
        if spf_text:
            category = classify_spf(spf_text)
            return category, spf_text, ""
        else:
            return "no_spf", "", ""
    except dns.resolver.NoAnswer:
        # The DNS response had no TXT answer
        return "no_spf", "", "NoAnswer: no TXT record found"
    except dns.resolver.NXDOMAIN:
        return "error", "", "NXDOMAIN: domain does not exist"
    except dns.resolver.Timeout:
        return "error", "", "Timeout"
    except dns.exception.DNSException as e:
        return "error", "", f"DNSException: {e}"
    except Exception as e:
        return "error", "", f"Unexpected: {e}"

# --- CLI and file handling -----------------------------------------------


def process_csv(input_path, output_path,
                rate_limit_seconds=0.2,
                start_from=None,
                retry_failed=False):
    resolver = dns.resolver.Resolver()
    # Optionally: set custom nameservers
    # resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 5
    resolver.lifetime = 8

    seen = 0
    total = 0
    results_written = 0

    # If output file exists, append; otherwise create with header
    mode = "a" if start_from else "w"
    with open(input_path, newline="") as inf, open(output_path, mode, newline="") as outf:
        reader = csv.reader(inf)
        writer = csv.writer(outf)
        # If we're creating a brand new file, write header
        if mode == "w":
            writer.writerow(["domain", "category", "spf_record", "error"])

        for row in reader:
            if not row:
                continue
            domain = row[1].strip()
            if not domain or domain.startswith("#"):
                continue
            total += 1
            # Optionally skip until start_from (resume)
            if start_from and total < start_from:
                continue

            category, spf_text, error = check_spf_for_domain(domain, resolver)
            # write result
            writer.writerow([domain, category, spf_text, error])
            results_written += 1

            # console output for progress
            print(f"{domain:40} → {category} {'('+error+')' if error else ''}")

            # polite rate limiting (don't flood resolvers)
            time.sleep(rate_limit_seconds)

    print(
        f"\nDone. Processed {results_written} domains. Output: {output_path}")


# --- Entrypoint ----------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Check SPF records for domains (authorized use only).")
    ap.add_argument(
        "input_csv", help="Input CSV file with domains (one per row)")
    ap.add_argument(
        "output_csv", help="Output CSV file (will be created/appended)")
    ap.add_argument("--rate", type=float, default=0.2,
                    help="Seconds between DNS queries (default 0.2s)")
    ap.add_argument("--start", type=int, default=0,
                    help="Skip first N domains (useful to resume)")
    args = ap.parse_args()

    process_csv(args.input_csv, args.output_csv,
                rate_limit_seconds=args.rate, start_from=args.start)


if __name__ == "__main__":
    main()

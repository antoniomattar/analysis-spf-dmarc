import csv
import spf
import socket
import requests
import os
from time import sleep


OUTPUT_FILE = "spf_results.csv"
INPUT_FILE = "data/top-1m.csv"


def get_public_ip():
    """Return the real public IP of this machine."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return None


def get_hostname():
    return socket.gethostname()


def check_spf(domain, sender_local="test"):
    """Perform an SPF check using dynamic MAIL FROM, public IP, and HELO."""
    ip = get_public_ip()
    helo = get_hostname()
    sender = f"{sender_local}@{domain}"

    if not ip:
        return ("error", "Could not determine public IP")

    try:
        result, explanation = spf.check2(i=ip, s=sender, h=helo)
    except Exception as e:
        return ("error", str(e))

    return (result, explanation)


def load_already_done(output_csv):
    """Return a set of domains already processed in the output CSV."""
    if not os.path.exists(output_csv):
        return set()

    done = set()
    with open(output_csv, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            done.add(row.get("domain", "").strip())
    return done


def analyze_csv_incremental(input_csv, output_csv, sleep_seconds=0):
    """
    Process domains incrementally, append results immediately,
    and skip domains already processed.
    """

    public_ip = get_public_ip()
    helo = get_hostname()

    if not public_ip:
        raise RuntimeError("Unable to determine public IP")

    # Load processed domains to allow safe resume
    done_domains = load_already_done(output_csv)
    print(f"🔄 Resuming… {len(done_domains)} domains already processed.")

    # Open output CSV in append mode
    file_exists = os.path.exists(output_csv)
    out = open(output_csv, "a", newline='', encoding="utf-8")
    writer = csv.DictWriter(out, fieldnames=[
        "domain", "public_ip", "helo", "mail_from",
        "spf_result", "explanation"
    ])

    # Write header only once
    if not file_exists:
        writer.writeheader()
        out.flush()

    with open(input_csv, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            domain = row.get("domain", "").strip()
            if not domain:
                continue

            # Skip already processed domains
            if domain in done_domains:
                continue

            spf_result, explanation = check_spf(domain)

            writer.writerow({
                "domain": domain,
                "public_ip": public_ip,
                "helo": helo,
                "mail_from": f"test@{domain}",
                "spf_result": spf_result,
                "explanation": explanation
            })

            out.flush()  # 🔥 Immediate write to disk — safe on interruption

            print(f"[✓] {domain} → {spf_result} ({explanation})")

            if sleep_seconds > 0:
                sleep(sleep_seconds)  # Optional throttle

    out.close()
    print(f"\n🎉 Analysis finished. Results saved to: {output_csv}")


if __name__ == "__main__":
    analyze_csv_incremental(INPUT_FILE, OUTPUT_FILE, sleep_seconds=0)

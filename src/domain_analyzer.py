#!/usr/bin/env python3
"""Domain Analysis Pipeline for SPF/DMARC Security Assessment (Upgraded)

Implements RFC-faithful improvements requested:
  A) SPF identity split (MAIL FROM vs HELO) and correct handling of multiple SPF records.
  B) DMARC SPF-alignment evaluation (strict/relaxed) + RFC 7489 policy selection.
  C) Organizational domain discovery using the Public Suffix List (PSL) and DMARC fallback.
  D) SPF macro detection + RFC-style macro expansion for exists: (and general templates).
  E) Include-chain trust scoring with structured evidence (DNS-only heuristics).
  G) Optional SMTP probing via swaks to capture stage decisions (RCPT/DATA accept/reject).

Safety/ethics note:
  The SMTP probing feature is intended for testing domains/addresses you control or have
  explicit permission to test. Use a sink mailbox you own.
"""

import argparse
import csv
import json
import logging
import os
import re
import socket
import subprocess
import sys
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from time import sleep
from typing import Dict, List, Optional, Set, Tuple

import dns.exception
import dns.resolver
import spf

try:
    # PSL helper for RFC 7489 Organizational Domain discovery
    from publicsuffix2 import get_sld
except Exception:  # pragma: no cover
    get_sld = None


# =============================================================================
# CONFIG
# =============================================================================

DNS_TIMEOUT = 5.0
MAX_DNS_RETRIES = 3
RETRY_BACKOFF_BASE = 2
MAX_INCLUDE_DEPTH = 10

# swaks probing defaults
SWAKS_TIMEOUT_SEC = 20


CSV_FIELDNAMES = [
    # identity
    "Domain_to_be_spoofed",
    "from_ip",
    "helo",

    # SPF raw + parse
    "its_spf_record",
    "spf_record_status",  # ok | none | permerror_multiple | temperror
    "has_ptr",
    "has_include",
    "dns_lookup_count",
    "unregistered_domain_in_include",
    "spf_all_qualifier",
    "spf_redirect",
    "spf_exp",

    # SPF A) identity split
    "spf_mailfrom_result",
    "spf_helo_result",
    "spf_best_result",  # if any passes -> pass else best-effort

    # SPF D) macro detection
    "spf_macro_used",
    "spf_macro_mechanisms",
    "spf_exists_expanded",  # expanded exists: domains for the simulated ip
    "spf_macro_risk_note",

    # DMARC raw + parse
    "its_dmarc_record",
    "dmarc_record_status",  # ok | none | permerror_multiple | temperror
    "dmarc_record_domain",  # where record was found (_dmarc.X)
    "dmarc_fallback_used",
    "dmarc_org_domain",
    "dmarc_policy",
    "dmarc_subdomain_policy",
    "dmarc_pct",
    "dmarc_rua",
    "dmarc_ruf",
    "dmarc_aspf",
    "dmarc_adkim",
    "dmarc_fo",
    "dmarc_ri",

    # DMARC B) alignment outputs
    "dmarc_spf_aligned_mailfrom",
    "dmarc_spf_aligned_helo",
    "dmarc_spf_aligned_pass",
    "dmarc_effective_policy",

    # E) include chain trust
    "include_trust_score",
    "include_trust_details_json",

    # G) SMTP probe
    "smtp_probe_enabled",
    "smtp_server",
    "smtp_stage_decision",
    "smtp_transcript_path",

    # manual annotation
    "what_happened",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================


@dataclass
class SPFRecord:
    raw_record: str
    has_ptr: bool
    has_include: bool
    includes: List[str]
    dns_lookup_count: int
    unregistered_includes: List[str]
    redirect: Optional[str]
    exp: Optional[str]
    all_qualifier: str
    macro_used: bool
    macro_mechanisms: List[str]
    exists_expanded: List[str]


@dataclass
class DMARCRecord:
    raw_record: str
    policy: str
    subdomain_policy: Optional[str]
    rua: Optional[str]
    ruf: Optional[str]
    pct: Optional[str]
    adkim: Optional[str]
    aspf: Optional[str]
    fo: Optional[str]
    ri: Optional[str]


@dataclass
class DomainAnalysis:
    domain: str
    from_ip: str
    helo: str

    spf_record: Optional[SPFRecord]
    spf_record_status: str
    spf_mailfrom_result: str
    spf_helo_result: str
    spf_best_result: str

    dmarc_record: Optional[DMARCRecord]
    dmarc_record_status: str
    dmarc_record_domain: str
    dmarc_fallback_used: bool
    dmarc_org_domain: str
    dmarc_effective_policy: str

    dmarc_spf_aligned_mailfrom: bool
    dmarc_spf_aligned_helo: bool
    dmarc_spf_aligned_pass: bool

    include_trust_score: int
    include_trust_details: Dict

    smtp_probe_enabled: bool
    smtp_server: str
    smtp_stage_decision: str
    smtp_transcript_path: str


# =============================================================================
# LOGGING
# =============================================================================


def setup_logging(log_level=logging.INFO):
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# =============================================================================
# DNS
# =============================================================================


def dns_query_with_retry(domain: str, record_type: str = "TXT", max_retries: int = MAX_DNS_RETRIES) -> Optional[List[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    for attempt in range(max_retries):
        try:
            answers = resolver.resolve(domain, record_type)
            if record_type == "TXT":
                out: List[str] = []
                for answer in answers:
                    parts: List[str] = []
                    for s in answer.strings:
                        parts.append(s.decode("utf-8", errors="ignore")
                                     if isinstance(s, (bytes, bytearray)) else str(s))
                    out.append("".join(parts))
                return out
            return [str(a) for a in answers]

        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            if attempt < max_retries - 1:
                wait_time = RETRY_BACKOFF_BASE ** attempt
                logging.warning(
                    f"DNS timeout for {domain}, retrying in {wait_time}s...")
                sleep(wait_time)
            else:
                return None
        except dns.exception.DNSException as e:
            logging.error(f"DNS error for {domain}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected DNS error for {domain}: {e}")
            return None

    return None


# =============================================================================
# SPF (RFC 7208)
# =============================================================================


def get_spf_record_rfc(domain: str) -> Tuple[Optional[str], str]:
    """Return (spf_record, status).

    RFC 7208: multiple v=spf1 records => permerror.
    """
    txt = dns_query_with_retry(domain, "TXT")
    if not txt:
        return None, "none"

    spfs = [r.strip() for r in txt if r.strip().lower().startswith("v=spf1")]
    if not spfs:
        return None, "none"
    if len(spfs) > 1:
        # Caller can treat as permerror, but we still preserve the raw evidence.
        return " || ".join(spfs), "permerror_multiple"
    return spfs[0], "ok"


_SPF_MACRO_PATTERN = re.compile(r"%\{[^}]+\}")


def _spf_macro_expand(template: str, *, ip: str, sender: str, helo: str, domain: str) -> str:
    """RFC 7208 §7 macro expansion (pragmatic implementation).

    Supports %{s} %{l} %{o} %{d} %{i} %{v} %{h} and modifiers (digits + r + delimiters).
    This is sufficient for exists: macro analysis and most real-world records.

    Notes:
      - Escapes: "%%" -> "%", "%_" -> space, "%-" -> "%20".
      - If expansion fails, returns a best-effort string.
    """
    # Escapes first
    s = template.replace("%%", "%").replace("%_", " ").replace("%-", "%20")

    def value_for(letter: str) -> str:
        letter = letter.lower()
        try:
            if letter == "s":
                return sender
            if letter == "l":
                return sender.split("@", 1)[0] if "@" in sender else sender
            if letter == "o":
                return sender.split("@", 1)[1] if "@" in sender else domain
            if letter == "d":
                return domain
            if letter == "i":
                return ip
            if letter == "v":
                return "in-addr" if ipaddress.ip_address(ip).version == 4 else "ip6"
            if letter == "h":
                return helo
        except Exception:
            return ""
        return ""

    def split_ip_parts(ip_str: str) -> List[str]:
        addr = ipaddress.ip_address(ip_str)
        if addr.version == 4:
            return ip_str.split(".")
        # IPv6: RFC macro i uses "nibble format" when used with reverse modifiers commonly.
        # We'll return full hex nibbles.
        expanded = addr.exploded.replace(":", "")
        return list(expanded)

    def apply_transform(raw: str, ip_raw: bool, spec: str) -> str:
        # spec grammar: <letter> [<digits>] ['r'] [<delims>]
        # We receive spec without surrounding %{ }
        letter = spec[0]
        rest = spec[1:]

        # digits
        m = re.match(r"(\d+)?(r)?(.*)", rest)
        if not m:
            return raw
        num_s, rflag, delims = m.group(1), m.group(2), m.group(3)
        num = int(num_s) if num_s else None
        reverse = bool(rflag)

        # delimiters
        if delims == "":
            delims_set = {"."}
        else:
            delims_set = set(delims)

        if ip_raw:
            parts = split_ip_parts(raw)
        else:
            # split on any delimiter in delims_set
            regex = "[" + re.escape("".join(sorted(delims_set))) + "]+"
            parts = [p for p in re.split(regex, raw) if p != ""]

        if reverse:
            parts = list(reversed(parts))
        if num is not None:
            parts = parts[:num]

        return ".".join(parts)

    def repl(mobj: re.Match) -> str:
        body = mobj.group(0)[2:-1]  # strip %{ }
        if not body:
            return ""
        letter = body[0].lower()
        raw = value_for(letter)
        ip_raw = (letter == "i")
        try:
            return apply_transform(raw, ip_raw, body)
        except Exception:
            return raw

    return _SPF_MACRO_PATTERN.sub(repl, s)


def parse_spf(spf_str: str, from_ip: str, sender: str, helo: str, domain: str,
              visited: Optional[Set[str]] = None, depth: int = 0) -> SPFRecord:
    if visited is None:
        visited = set()

    has_ptr = False
    has_include = False
    includes: List[str] = []
    unregistered_includes: List[str] = []
    dns_lookup_count = 0
    redirect = None
    exp = None
    all_qualifier = "?"

    macro_used = False
    macro_mechs: List[str] = []
    exists_expanded: List[str] = []

    tokens = spf_str.split()
    for token in tokens:
        token = token.strip()

        # Macro detection
        if "%{" in token or "%_" in token or "%-" in token or "%%" in token:
            macro_used = True
            if _SPF_MACRO_PATTERN.search(token) or "%_" in token or "%-" in token:
                macro_mechs.append(token)

        # ptr (discouraged)
        if re.search(r"(^|[:/])ptr($|\b)", token.lower()):
            has_ptr = True
            dns_lookup_count += 1

        # include
        if token.startswith("include:"):
            has_include = True
            include_domain = token.split(":", 1)[1]
            includes.append(include_domain)
            dns_lookup_count += 1

            if include_domain not in visited and depth < MAX_INCLUDE_DEPTH:
                visited.add(include_domain)
                txt = dns_query_with_retry(include_domain, "TXT")
                if not txt:
                    unregistered_includes.append(include_domain)
                else:
                    included_spf, status = get_spf_record_rfc(include_domain)
                    if included_spf and status == "ok":
                        included_parsed = parse_spf(
                            included_spf,
                            from_ip=from_ip,
                            sender=sender,
                            helo=helo,
                            domain=include_domain,
                            visited=visited,
                            depth=depth + 1,
                        )
                        dns_lookup_count += included_parsed.dns_lookup_count

        # redirect
        elif token.startswith("redirect="):
            redirect = token.split("=", 1)[1]
            dns_lookup_count += 1

        # exp
        elif token.startswith("exp="):
            exp = token.split("=", 1)[1]
            dns_lookup_count += 1

        # exists
        elif token.startswith("exists:"):
            dns_lookup_count += 1
            rhs = token.split(":", 1)[1]
            if "%" in rhs:
                expanded = _spf_macro_expand(
                    rhs, ip=from_ip, sender=sender, helo=helo, domain=domain)
                exists_expanded.append(expanded)
            else:
                exists_expanded.append(rhs)

        # other mechanisms that cost DNS lookups (RFC 7208 §4.6.4)
        elif any(token.startswith(prefix) for prefix in ["a:", "a/", "mx:", "mx/"]):
            dns_lookup_count += 1
        elif token == "a":
            dns_lookup_count += 1
        elif token == "mx":
            dns_lookup_count += 1

        # all qualifier
        elif token.startswith(("-all", "~all", "+all", "?all")):
            all_qualifier = token[0]

    # normalize macro_mechs
    macro_mechs = sorted(set(macro_mechs))
    exists_expanded = sorted(set(exists_expanded))

    return SPFRecord(
        raw_record=spf_str,
        has_ptr=has_ptr,
        has_include=has_include,
        includes=includes,
        dns_lookup_count=dns_lookup_count,
        unregistered_includes=unregistered_includes,
        redirect=redirect,
        exp=exp,
        all_qualifier=all_qualifier,
        macro_used=macro_used,
        macro_mechanisms=macro_mechs,
        exists_expanded=exists_expanded,
    )


def evaluate_spf_identities(ip: str, mail_from: str, helo: str) -> Tuple[str, str, str]:
    """A) Evaluate SPF twice: MAIL FROM identity and HELO identity.

    Returns (mailfrom_result, helo_result, best_result).
    """

    def safe_check(i: str, s: str, h: str) -> str:
        try:
            res, _exp = spf.check2(i=i, s=s, h=h)
            return res
        except Exception as e:
            logging.error(f"SPF check error (i={i}, s={s}, h={h}): {e}")
            return "temperror"

    r_mail = safe_check(ip, mail_from, helo)
    # RFC 7208: if MAIL FROM is empty, receivers use HELO. We still evaluate both for research.
    r_helo = safe_check(ip, "", helo)

    # best effort ordering
    order = {"pass": 6, "fail": 1, "softfail": 2, "neutral": 3,
             "none": 0, "permerror": 4, "temperror": 5}
    best = r_mail if order.get(r_mail, 0) >= order.get(r_helo, 0) else r_helo
    if r_mail == "pass" or r_helo == "pass":
        best = "pass"
    return r_mail, r_helo, best


# =============================================================================
# DMARC (RFC 7489)
# =============================================================================


def get_organizational_domain(domain: str) -> str:
    """C) Determine Organizational Domain using PSL.

    RFC 7489 relies on PSL for organizational domain boundaries.
    """
    d = domain.strip(".").lower()
    if not d:
        return ""
    if get_sld is None:
        # Fallback: last two labels (not PSL-correct). We *warn* to avoid silent misclassification.
        parts = d.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return d
    try:
        sld = get_sld(d)
        return sld or d
    except Exception:
        return d


def get_dmarc_record_rfc(domain: str) -> Tuple[Optional[str], str, bool, str]:
    """C) DMARC record discovery per RFC 7489 §6.6.3.

    Returns (record, status, fallback_used, record_domain).
    status: ok | none | permerror_multiple | temperror
    record_domain: the domain component used after _dmarc.
    """
    d = domain.strip(".").lower()
    org = get_organizational_domain(d)

    def fetch(dmarc_target: str) -> Tuple[Optional[str], str]:
        txt = dns_query_with_retry(f"_dmarc.{dmarc_target}", "TXT")
        if not txt:
            return None, "none"
        recs = [r.strip()
                for r in txt if r.strip().lower().startswith("v=dmarc1")]
        if not recs:
            return None, "none"
        if len(recs) > 1:
            return " || ".join(recs), "permerror_multiple"
        return recs[0], "ok"

    rec, status = fetch(d)
    if rec is not None:
        return rec, status, False, d

    # fallback to organizational domain if different
    if org and org != d:
        rec2, status2 = fetch(org)
        if rec2 is not None:
            return rec2, status2, True, org

    return None, "none", False, ""


def parse_dmarc(dmarc_str: str) -> DMARCRecord:
    policy = "none"
    subdomain_policy = None
    rua = None
    ruf = None
    pct = None
    adkim = None
    aspf = None
    fo = None
    ri = None

    tags = [t.strip() for t in dmarc_str.split(";") if t.strip()]
    for tag in tags:
        if "=" not in tag:
            continue
        k, v = tag.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "p":
            policy = v
        elif k == "sp":
            subdomain_policy = v
        elif k == "rua":
            rua = v
        elif k == "ruf":
            ruf = v
        elif k == "pct":
            pct = v
        elif k == "adkim":
            adkim = v
        elif k == "aspf":
            aspf = v
        elif k == "fo":
            fo = v
        elif k == "ri":
            ri = v

    return DMARCRecord(
        raw_record=dmarc_str,
        policy=policy,
        subdomain_policy=subdomain_policy,
        rua=rua,
        ruf=ruf,
        pct=pct,
        adkim=adkim,
        aspf=aspf,
        fo=fo,
        ri=ri,
    )


def _extract_domain_from_email(addr: str) -> str:
    if not addr:
        return ""
    if "@" not in addr:
        return addr.strip().lower().strip(".")
    return addr.split("@", 1)[1].strip().lower().strip(".")


def dmarc_spf_alignment(from_domain: str, spf_domain: str, mode: str) -> bool:
    """B) RFC 7489 alignment function for SPF identifiers.

    Strict (s): exact match.
    Relaxed (r): Organizational-domain match.
    """
    from_domain = from_domain.strip(".").lower()
    spf_domain = spf_domain.strip(".").lower()
    mode = (mode or "r").lower()

    if not from_domain or not spf_domain:
        return False

    if mode == "s":
        return from_domain == spf_domain

    # relaxed: compare organizational domains
    return get_organizational_domain(from_domain) == get_organizational_domain(spf_domain)


def dmarc_effective_policy(dmarc: Optional[DMARCRecord], from_domain: str, org_domain: str) -> str:
    """B) Compute effective DMARC policy for the RFC5322.From domain.

    If from_domain is a subdomain of org_domain and sp= is set, use sp, else p.
    If no DMARC record: return "none".
    """
    if not dmarc:
        return "none"
    p = (dmarc.policy or "none").lower()
    sp = (dmarc.subdomain_policy or "").lower() or None

    fd = from_domain.strip(".").lower()
    org = org_domain.strip(".").lower()

    if fd and org and fd != org and fd.endswith("." + org):
        return sp if sp else p
    return p


# =============================================================================
# E) Include-chain trust scoring (DNS-only heuristics)
# =============================================================================


def compute_include_trust(domain: str, spf_rec: Optional[SPFRecord]) -> Tuple[int, Dict]:
    """Heuristic trust score for SPF include chain.

    This is *not* an RFC concept; it is a research metric.
    Only DNS-derived evidence is used (no WHOIS scraping).
    """
    if not spf_rec or not spf_rec.includes:
        return 100, {"includes": [], "notes": ["no_includes"]}

    org = get_organizational_domain(domain)
    details = {"org_domain": org, "includes": [], "notes": []}

    score = 100
    for inc in spf_rec.includes:
        inc_l = inc.strip(".").lower()
        inc_org = get_organizational_domain(inc_l)
        third_party = (inc_org != org)

        # DNS existence
        txt = dns_query_with_retry(inc_l, "TXT")
        exists = bool(txt)
        if not exists:
            score -= 35

        inc_spf, inc_spf_status = get_spf_record_rfc(inc_l)
        if inc_spf_status == "none":
            score -= 10
        if inc_spf_status == "permerror_multiple":
            score -= 15

        # DMARC presence (weak signal for include domains)
        inc_dmarc, inc_dmarc_status, inc_fb, inc_rd = get_dmarc_record_rfc(
            inc_l)
        dmarc_present = inc_dmarc is not None

        # third party risk
        if third_party:
            score -= 10

        # lookup budget risk from child SPF
        child_lookups = 0
        if inc_spf and inc_spf_status == "ok":
            try:
                parsed_child = parse_spf(
                    inc_spf,
                    from_ip="127.0.0.1",  # neutral placeholder
                    sender=f"test@{domain}",
                    helo=domain,
                    domain=inc_l,
                    visited=set(),
                    depth=0,
                )
                child_lookups = parsed_child.dns_lookup_count
            except Exception:
                child_lookups = 0
        if child_lookups >= 8:
            score -= 10

        details["includes"].append(
            {
                "include": inc_l,
                "include_org": inc_org,
                "third_party": third_party,
                "dns_exists": exists,
                "spf_status": inc_spf_status,
                "dmarc_present": dmarc_present,
                "child_dns_lookup_count": child_lookups,
            }
        )

    # unregistered includes already detected in SPF parse => penalize strongly
    if spf_rec.unregistered_includes:
        score -= min(50, 20 * len(spf_rec.unregistered_includes))
        details["notes"].append("unregistered_includes_present")

    # clamp
    score = max(0, min(100, score))
    return score, details


# =============================================================================
# G) SMTP probing via swaks
# =============================================================================


def run_swaks_probe(
    *,
    smtp_server: str,
    mail_from: str,
    rcpt_to: str,
    helo: str,
    subject: str,
    body: str,
    timeout_sec: int = SWAKS_TIMEOUT_SEC,
    transcript_dir: str = "output/smtp_transcripts",
) -> Tuple[str, str]:
    """Run swaks and return (stage_decision, transcript_path)."""

    os.makedirs(transcript_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_srv = re.sub(r"[^A-Za-z0-9_.-]", "_", smtp_server)
    transcript_path = os.path.join(
        transcript_dir, f"swaks_{safe_srv}_{ts}.txt")

    # swaks: keep it simple; do NOT attempt to bypass auth.
    # Use --header to make sure Subject is correct and deterministic.
    cmd = [
        "swaks",
        f"--server={smtp_server}",
        f"--from={mail_from}",
        f"--to={rcpt_to}",
        f"--ehlo={helo}",
        "--quit-after=DATA",  # stops after server accepts/rejects DATA block
        "--header", f"Subject: {subject}",
        "--body", body,
        "--timeout", str(timeout_sec),
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except FileNotFoundError:
        return "swaks_not_installed", ""
    except Exception as e:
        return f"swaks_error:{e}", ""

    with open(transcript_path, "w", encoding="utf-8") as f:
        f.write(out)

    # Parse stage decision from transcript
    # swaks prints SMTP dialogue lines; we look for common milestones
    stage = "unknown"
    if re.search(r"<\-\s+5\d\d\b.*RCPT", out, re.IGNORECASE):
        stage = "rcpt_rejected"
    elif re.search(r"<\-\s+354\b", out):
        stage = "data_accepted_354"
    elif re.search(r"<\-\s+5\d\d\b.*DATA", out, re.IGNORECASE):
        stage = "data_rejected"
    elif re.search(r"<\-\s+250\b.*queued", out, re.IGNORECASE) or re.search(r"<\-\s+250\s+2\.0\.0", out):
        stage = "accepted_queued"
    elif re.search(r"Connection.*failed", out, re.IGNORECASE):
        stage = "connect_failed"

    return stage, transcript_path


# =============================================================================
# PIPELINE
# =============================================================================


def analyze_domain(
    domain: str,
    from_ip: str,
    helo: str,
    smtp_probe: bool = False,
    smtp_server: str = "",
    smtp_rcpt_to: str = "",
    smtp_subject: str = "DMARC/SPF research probe",
    smtp_body: str = "This is an automated authentication research probe.",
    smtp_transcript_dir: str = "output/smtp_transcripts",
) -> DomainAnalysis:
    domain = domain.strip().lower().strip(".")
    logging.info(f"Analyzing {domain}")

    # SPF
    spf_raw, spf_status = get_spf_record_rfc(domain)
    spf_rec = None
    spf_macro_risk_note = ""
    if spf_raw and spf_status in ("ok", "permerror_multiple"):
        # For permerror_multiple we still parse the first component for signals
        spf_to_parse = spf_raw.split(" || ", 1)[0]
        sender = f"test@{domain}"
        spf_rec = parse_spf(spf_to_parse, from_ip=from_ip,
                            sender=sender, helo=helo, domain=domain)
        if spf_rec.macro_used:
            spf_macro_risk_note = "macros_present; exists: can create per-IP DNS queries (see RFC7208 §7)"

    # SPF A) identity split
    mail_from = f"test@{domain}"
    spf_mail, spf_helo_res, spf_best = evaluate_spf_identities(
        from_ip, mail_from, helo)

    # DMARC C)
    dmarc_raw, dmarc_status, dmarc_fallback, dmarc_rd = get_dmarc_record_rfc(
        domain)
    dmarc_rec = parse_dmarc(dmarc_raw) if dmarc_raw else None
    org = get_organizational_domain(domain)

    # DMARC B) alignment
    from_domain = domain  # RFC5322.From domain in your simulation
    aspf_mode = (dmarc_rec.aspf if dmarc_rec and dmarc_rec.aspf else "r")

    aligned_mail = (spf_mail == "pass") and dmarc_spf_alignment(
        from_domain, _extract_domain_from_email(mail_from), aspf_mode)
    aligned_helo = (spf_helo_res == "pass") and dmarc_spf_alignment(
        from_domain, helo, aspf_mode)
    aligned_pass = aligned_mail or aligned_helo

    eff_pol = dmarc_effective_policy(dmarc_rec, from_domain, org)

    # E) include trust
    trust_score, trust_details = compute_include_trust(domain, spf_rec)

    # G) SMTP probe (optional)
    smtp_stage = ""
    transcript_path = ""
    if smtp_probe:
        if not smtp_server or not smtp_rcpt_to:
            smtp_stage = "smtp_probe_missing_params"
        else:
            smtp_stage, transcript_path = run_swaks_probe(
                smtp_server=smtp_server,
                mail_from=mail_from,
                rcpt_to=smtp_rcpt_to,
                helo=helo,
                subject=smtp_subject,
                body=smtp_body,
                transcript_dir=smtp_transcript_dir,
            )

    return DomainAnalysis(
        domain=domain,
        from_ip=from_ip,
        helo=helo,
        spf_record=spf_rec,
        spf_record_status=spf_status,
        spf_mailfrom_result=spf_mail,
        spf_helo_result=spf_helo_res,
        spf_best_result=spf_best,
        dmarc_record=dmarc_rec,
        dmarc_record_status=dmarc_status,
        dmarc_record_domain=dmarc_rd,
        dmarc_fallback_used=dmarc_fallback,
        dmarc_org_domain=org,
        dmarc_effective_policy=eff_pol,
        dmarc_spf_aligned_mailfrom=bool(aligned_mail),
        dmarc_spf_aligned_helo=bool(aligned_helo),
        dmarc_spf_aligned_pass=bool(aligned_pass),
        include_trust_score=trust_score,
        include_trust_details=trust_details,
        smtp_probe_enabled=bool(smtp_probe),
        smtp_server=smtp_server,
        smtp_stage_decision=smtp_stage,
        smtp_transcript_path=transcript_path,
    )


def analysis_to_csv_row(a: DomainAnalysis) -> Dict[str, str]:
    spf_rec = a.spf_record
    dmarc = a.dmarc_record

    return {
        "Domain_to_be_spoofed": a.domain,
        "from_ip": a.from_ip,
        "helo": a.helo,

        "its_spf_record": spf_rec.raw_record if spf_rec else (""),
        "spf_record_status": a.spf_record_status,
        "has_ptr": "True" if spf_rec and spf_rec.has_ptr else "False",
        "has_include": "True" if spf_rec and spf_rec.has_include else "False",
        "dns_lookup_count": str(spf_rec.dns_lookup_count) if spf_rec else "0",
        "unregistered_domain_in_include": ",".join(spf_rec.unregistered_includes) if spf_rec and spf_rec.unregistered_includes else "None",
        "spf_all_qualifier": spf_rec.all_qualifier if spf_rec else "",
        "spf_redirect": spf_rec.redirect if spf_rec and spf_rec.redirect else "",
        "spf_exp": spf_rec.exp if spf_rec and spf_rec.exp else "",

        "spf_mailfrom_result": a.spf_mailfrom_result,
        "spf_helo_result": a.spf_helo_result,
        "spf_best_result": a.spf_best_result,

        "spf_macro_used": "True" if spf_rec and spf_rec.macro_used else "False",
        "spf_macro_mechanisms": ";".join(spf_rec.macro_mechanisms) if spf_rec and spf_rec.macro_mechanisms else "",
        "spf_exists_expanded": ";".join(spf_rec.exists_expanded) if spf_rec and spf_rec.exists_expanded else "",
        "spf_macro_risk_note": "macros_present" if (spf_rec and spf_rec.macro_used) else "",

        "its_dmarc_record": dmarc.raw_record if dmarc else "",
        "dmarc_record_status": a.dmarc_record_status,
        "dmarc_record_domain": a.dmarc_record_domain,
        "dmarc_fallback_used": "True" if a.dmarc_fallback_used else "False",
        "dmarc_org_domain": a.dmarc_org_domain,
        "dmarc_policy": dmarc.policy if dmarc else "",
        "dmarc_subdomain_policy": dmarc.subdomain_policy if dmarc and dmarc.subdomain_policy else "",
        "dmarc_pct": dmarc.pct if dmarc and dmarc.pct else "100" if dmarc else "",
        "dmarc_rua": dmarc.rua if dmarc and dmarc.rua else "",
        "dmarc_ruf": dmarc.ruf if dmarc and dmarc.ruf else "",
        "dmarc_aspf": dmarc.aspf if dmarc and dmarc.aspf else "r" if dmarc else "",
        "dmarc_adkim": dmarc.adkim if dmarc and dmarc.adkim else "r" if dmarc else "",
        "dmarc_fo": dmarc.fo if dmarc and dmarc.fo else "0" if dmarc else "",
        "dmarc_ri": dmarc.ri if dmarc and dmarc.ri else "86400" if dmarc else "",

        "dmarc_spf_aligned_mailfrom": "True" if a.dmarc_spf_aligned_mailfrom else "False",
        "dmarc_spf_aligned_helo": "True" if a.dmarc_spf_aligned_helo else "False",
        "dmarc_spf_aligned_pass": "True" if a.dmarc_spf_aligned_pass else "False",
        "dmarc_effective_policy": a.dmarc_effective_policy,

        "include_trust_score": str(a.include_trust_score),
        "include_trust_details_json": json.dumps(a.include_trust_details, ensure_ascii=False),

        "smtp_probe_enabled": "True" if a.smtp_probe_enabled else "False",
        "smtp_server": a.smtp_server,
        "smtp_stage_decision": a.smtp_stage_decision,
        "smtp_transcript_path": a.smtp_transcript_path,

        "what_happened": "",
    }


def load_processed_domains(output_csv: str) -> Set[str]:
    if not os.path.exists(output_csv):
        return set()
    processed: Set[str] = set()
    try:
        with open(output_csv, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = (row.get("Domain_to_be_spoofed") or "").strip().lower()
                if d:
                    processed.add(d)
    except Exception as e:
        logging.error(f"Error loading processed domains: {e}")
    return processed


def save_row(writer: csv.DictWriter, row: Dict[str, str], fh):
    writer.writerow(row)
    fh.flush()
    os.fsync(fh.fileno())


def run_analysis(
    input_csv: str,
    output_csv: str,
    from_ip: str,
    helo: str,
    sleep_seconds: float = 0.0,
    limit: Optional[int] = None,
    smtp_probe: bool = False,
    smtp_server: str = "",
    smtp_rcpt_to: str = "",
    smtp_subject: str = "DMARC/SPF research probe",
    smtp_body: str = "This is an automated authentication research probe.",
    smtp_transcript_dir: str = "output/smtp_transcripts",
):
    processed = load_processed_domains(output_csv)
    logging.info(f"Loaded {len(processed)} already-processed domains")

    file_exists = os.path.exists(output_csv)
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    out_f = open(output_csv, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(out_f, fieldnames=CSV_FIELDNAMES)
    if not file_exists:
        writer.writeheader()
        out_f.flush()

    total_domains = 0
    processed_count = 0
    skipped_count = 0
    error_count = 0

    try:
        with open(input_csv, "r", newline="", encoding="utf-8") as in_f:
            reader = csv.DictReader(in_f)
            for row in reader:
                if limit and processed_count >= limit:
                    logging.info(
                        f"Reached limit of {limit} domains, stopping...")
                    break

                domain = (row.get("domain") or "").strip().lower()
                if not domain:
                    continue

                total_domains += 1
                if domain in processed:
                    skipped_count += 1
                    continue

                try:
                    analysis = analyze_domain(
                        domain=domain,
                        from_ip=from_ip,
                        helo=helo,
                        smtp_probe=smtp_probe,
                        smtp_server=smtp_server,
                        smtp_rcpt_to=smtp_rcpt_to,
                        smtp_subject=smtp_subject,
                        smtp_body=smtp_body,
                        smtp_transcript_dir=smtp_transcript_dir,
                    )
                    csv_row = analysis_to_csv_row(analysis)
                    save_row(writer, csv_row, out_f)
                    processed_count += 1

                    if processed_count % 10 == 0:
                        logging.info(
                            f"Progress: {processed_count} processed, {skipped_count} skipped")
                    if sleep_seconds > 0:
                        sleep(sleep_seconds)
                except Exception as e:
                    logging.error(f"Error processing {domain}: {e}")
                    error_count += 1
    finally:
        out_f.close()

    logging.info("=" * 60)
    logging.info("ANALYSIS COMPLETE")
    logging.info("=" * 60)
    logging.info(f"Total unique domains in input: {total_domains}")
    logging.info(f"New entries processed: {processed_count}")
    logging.info(f"Entries skipped: {skipped_count}")
    logging.info(f"Errors encountered: {error_count}")
    logging.info(f"Output saved to: {output_csv}")
    logging.info("=" * 60)


def run_single_domain_analysis(
    domain: str,
    output_csv: str,
    from_ip: str,
    helo: str,
    smtp_probe: bool = False,
    smtp_server: str = "",
    smtp_rcpt_to: str = "",
    smtp_subject: str = "DMARC/SPF research probe",
    smtp_body: str = "This is an automated authentication research probe.",
    smtp_transcript_dir: str = "output/smtp_transcripts",
):
    processed = load_processed_domains(output_csv)
    if domain.strip().lower() in processed:
        logging.warning(
            f"Domain {domain} already exists in output file, skipping...")
        return

    file_exists = os.path.exists(output_csv)
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "a", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()

        analysis = analyze_domain(
            domain=domain,
            from_ip=from_ip,
            helo=helo,
            smtp_probe=smtp_probe,
            smtp_server=smtp_server,
            smtp_rcpt_to=smtp_rcpt_to,
            smtp_subject=smtp_subject,
            smtp_body=smtp_body,
            smtp_transcript_dir=smtp_transcript_dir,
        )
        save_row(writer, analysis_to_csv_row(analysis), out_f)


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive SPF/DMARC analysis (RFC-faithful upgrades)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help='Input CSV with a "domain" column')
    src.add_argument("--domain", "-d", help="Single domain to analyze")

    parser.add_argument("--output", "-o", required=True,
                        help="Output CSV file")
    parser.add_argument("--from-ip", required=True,
                        help="Sender IP to simulate")
    parser.add_argument("--helo", required=True, help="HELO/EHLO hostname")
    parser.add_argument("--sleep", type=float, default=0.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--verbose", "-v", action="store_true")

    # G) SMTP probing (optional)
    parser.add_argument("--smtp-probe", action="store_true",
                        help="Enable SMTP probe via swaks")
    parser.add_argument("--smtp-server", default="",
                        help="SMTP server (MX hostname or IP) for swaks")
    parser.add_argument("--smtp-to", default="",
                        help="Recipient mailbox (sink) you control")
    parser.add_argument("--smtp-subject", default="DMARC/SPF research probe")
    parser.add_argument(
        "--smtp-body", default="This is an automated authentication research probe.")
    parser.add_argument("--smtp-transcripts",
                        default="output/smtp_transcripts")

    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    # PSL dependency warning
    if get_sld is None:
        logging.warning(
            "publicsuffix2 is not installed; organizational-domain detection will be approximate. "
            "Install with: pip install publicsuffix2"
        )

    output_path = args.output
    if os.path.dirname(output_path) == "":
        output_path = os.path.join("output", output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if args.domain:
        run_single_domain_analysis(
            domain=args.domain,
            output_csv=output_path,
            from_ip=args.from_ip,
            helo=args.helo,
            smtp_probe=args.smtp_probe,
            smtp_server=args.smtp_server,
            smtp_rcpt_to=args.smtp_to,
            smtp_subject=args.smtp_subject,
            smtp_body=args.smtp_body,
            smtp_transcript_dir=args.smtp_transcripts,
        )
    else:
        if not os.path.exists(args.input):
            logging.error(f"Input file not found: {args.input}")
            sys.exit(1)
        run_analysis(
            input_csv=args.input,
            output_csv=output_path,
            from_ip=args.from_ip,
            helo=args.helo,
            sleep_seconds=args.sleep,
            limit=args.limit,
            smtp_probe=args.smtp_probe,
            smtp_server=args.smtp_server,
            smtp_rcpt_to=args.smtp_to,
            smtp_subject=args.smtp_subject,
            smtp_body=args.smtp_body,
            smtp_transcript_dir=args.smtp_transcripts,
        )


if __name__ == "__main__":
    main()

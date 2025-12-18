#!/usr/bin/env python3
"""
SPF & DMARC Security Analyzer - Outil complet d'analyse
Projet académique - Analyse des vulnérabilités SPF/DMARC et détection d'attaques

Fonctionnalités:
- Analyse récursive des enregistrements SPF
- Analyse des politiques DMARC et rapports RUA/RUF
- Détection d'attaques ciblées (shadow SPF, DMARC hijacking, etc.)
- Scoring unifié de risque
- Génération de rapports détaillés JSON/CSV

DISCLAIMER: Cet outil est conçu pour la recherche académique et l'éducation
en sécurité uniquement. Il ne doit être utilisé que sur des domaines dont vous
avez l'autorisation d'analyser, ou dans le cadre d'une recherche éthique approuvée.
"""

import argparse
import csv
import json
import sys
from typing import List, Dict
from datetime import datetime

from src.utils.tranco_fetcher import fetch_tranco_list, load_domains_from_file
from src.analyzers.dmarc_analyzer import analyze_dmarc_security
from src.detectors.attack_detector import AttackDetector
from src.analyzers.spf_analyzer import SPFAnalyzer
from src.utils.analysis_findings import FindingsAnalyzer
from src.utils.spf_checker import check_spf, check_dmarc


def print_banner():
    """Affiche le banner du programme."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║      SPF & DMARC Security Analyzer - Feature Detection       ║
║           Academic Project - Security Research               ║
╚══════════════════════════════════════════════════════════════╝

Comprehensive Feature Detection: SPF + DMARC + Attack Vectors
Based on: RFC 7208 (SPF), RFC 7489 (DMARC), Security Best Practices

⚠️  ETHICAL USE ONLY - Academic research only
"""
    print(banner)


def analyze_domain(domain: str, verbose: bool = False) -> Dict:
    """
    Complete domain analysis: SPF + DMARC + Attack Vectors + Findings.

    Args:
        domain: Domain name to analyze
        verbose: Verbose output

    Returns:
        Complete analysis findings
    """
    if verbose:
        print(f"  Analyzing {domain}...", end=' ')

    try:
        # 1. SPF Analysis
        spf_analyzer = SPFAnalyzer()
        spf_result = spf_analyzer.analyze_domain(domain)

        # 2. DMARC Analysis
        dmarc_result = analyze_dmarc_security(domain)

        # 3. Attack Vector Detection
        attack_analysis = AttackDetector.detect_targeted_attack(
            domain, spf_result, dmarc_result
        )

        # 4. Consolidate all findings
        findings = FindingsAnalyzer.create_findings(
            domain, datetime.now().isoformat()
        )

        FindingsAnalyzer.merge_spf_findings(findings, spf_result)
        FindingsAnalyzer.merge_dmarc_findings(findings, dmarc_result)
        FindingsAnalyzer.merge_attack_findings(findings, attack_analysis)

        # Build complete result
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'findings': findings.to_dict(),

            # Raw analysis data
            'spf': {
                'has_spf': spf_result.has_spf,
                'raw_record': spf_result.spf_record.raw_record if spf_result.spf_record else None,
                'total_lookups': spf_result.total_lookups,
                'includes_count': len(spf_result.all_includes),
                'includes': list(spf_result.all_includes),
                'shadow_includes': spf_result.shadow_includes,
                'suspicious_includes': spf_result.suspicious_includes,
                'all_qualifier': spf_result.spf_record.all_qualifier.value if spf_result.spf_record and spf_result.spf_record.all_qualifier else None,
                'permissive_policy': spf_result.permissive_policy
            },

            # DMARC
            'dmarc': {
                'has_dmarc': dmarc_result.get('has_dmarc', False),
                'record': dmarc_result.get('dmarc_record'),
                'policy': dmarc_result.get('policy'),
                'subdomain_policy': dmarc_result.get('subdomain_policy'),
                'pct': dmarc_result.get('pct', 100),
                'rua_uris': dmarc_result.get('rua_uris', []),
                'ruf_uris': dmarc_result.get('ruf_uris', []),
                'rua_domains': dmarc_result.get('rua_domains', []),
                'ruf_domains': dmarc_result.get('ruf_domains', []),
            },

            # Attack Vectors
            'attack_vectors': {
                'is_attack_target': attack_analysis.is_attack_target,
                'is_attack_source': attack_analysis.is_attack_source,
                'attack_count': len(attack_analysis.detected_attacks),
                'attack_vectors': list(attack_analysis.attack_vectors),
                'attacks': [
                    {
                        'type': attack.attack_type.value,
                        'severity': attack.severity.name,
                        'description': attack.description,
                        'evidence': attack.evidence,
                        'mitigation': attack.mitigation
                    }
                    for attack in attack_analysis.detected_attacks
                ],
                'recommendations': attack_analysis.recommendations
            }
        }

        if verbose:
            findings_summary = findings.get_summary()
            critical = findings_summary.get('critical', 0)
            high = findings_summary.get('high', 0)
            total = findings_summary.get('total_findings', 0)
            print(
                f"✓ Found {total} findings (Critical: {critical}, High: {high})")

        return result

    except Exception as e:
        if verbose:
            print(f"✗ Error: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def export_to_csv(results: List[Dict], output_file: str):
    """
    Export results to CSV format.

    Args:
        results: List of analysis results
        output_file: Output file path
    """
    if not results:
        print("No results to export.")
        return

    fieldnames = [
        'domain',
        'timestamp',
        # SPF
        'spf_present',
        'spf_lookups',
        'spf_includes_count',
        'spf_shadow_includes',
        'spf_suspicious_includes',
        'spf_policy',
        # DMARC
        'dmarc_present',
        'dmarc_policy',
        'dmarc_subdomain_policy',
        'dmarc_pct',
        'dmarc_rua_count',
        'dmarc_ruf_count',
        # Findings
        'total_findings',
        'critical_findings',
        'high_findings',
        'medium_findings',
        'vulnerabilities_count',
        'attack_vectors_count',
        'configuration_issues_count',
        'compliance_issues_count',
        # Attack Vectors
        'is_attack_target',
        'is_attack_source',
        'attack_count',
        'error'
    ]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            if 'error' in result:
                row = {
                    'domain': result['domain'],
                    'timestamp': result.get('timestamp', ''),
                    'error': result['error']
                }
            else:
                spf = result.get('spf', {})
                dmarc = result.get('dmarc', {})
                attacks = result.get('attack_vectors', {})
                findings_data = result.get('findings', {})
                summary = findings_data.get('summary', {})

                row = {
                    'domain': result['domain'],
                    'timestamp': result.get('timestamp', ''),
                    # SPF
                    'spf_present': spf.get('has_spf', False),
                    'spf_lookups': spf.get('total_lookups', 0),
                    'spf_includes_count': spf.get('includes_count', 0),
                    'spf_shadow_includes': ','.join(spf.get('shadow_includes', [])),
                    'spf_suspicious_includes': ','.join(spf.get('suspicious_includes', [])),
                    'spf_policy': spf.get('all_qualifier', 'NONE'),
                    # DMARC
                    'dmarc_present': dmarc.get('has_dmarc', False),
                    'dmarc_policy': dmarc.get('policy', 'NONE'),
                    'dmarc_subdomain_policy': dmarc.get('subdomain_policy', 'NONE'),
                    'dmarc_pct': dmarc.get('pct', 100),
                    'dmarc_rua_count': len(dmarc.get('rua_uris', [])),
                    'dmarc_ruf_count': len(dmarc.get('ruf_uris', [])),
                    # Findings
                    'total_findings': summary.get('total_findings', 0),
                    'critical_findings': summary.get('critical', 0),
                    'high_findings': summary.get('high', 0),
                    'medium_findings': summary.get('medium', 0),
                    'vulnerabilities_count': summary.get('vulnerabilities', 0),
                    'attack_vectors_count': summary.get('attack_vectors', 0),
                    'configuration_issues_count': summary.get('configuration_issues', 0),
                    'compliance_issues_count': summary.get('compliance_issues', 0),
                    # Attack Vectors
                    'is_attack_target': attacks.get('is_attack_target', False),
                    'is_attack_source': attacks.get('is_attack_source', False),
                    'attack_count': attacks.get('attack_count', 0),
                    'error': ''
                }

            writer.writerow(row)

    print(f"✓ Results exported to {output_file}")


def export_to_json(results: List[Dict], output_file: str):
    """
    Export results to JSON format.

    Args:
        results: List of analysis results
        output_file: Output file path
    """
    output = {
        'metadata': {
            'tool': 'SPF & DMARC Security Analyzer',
            'version': '2.1',
            'timestamp': datetime.now().isoformat(),
            'domain_count': len(results),
            'analysis_components': [
                'SPF Analysis',
                'DMARC Analysis',
                'Attack Detection',
                'Feature Detection'
            ]
        },
        'results': results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"✓ Results exported to {output_file}")


def print_detailed_analysis(result: Dict):
    """
    Display detailed analysis for a single domain.

    Args:
        result: Analysis result for a single domain
    """
    if 'error' in result:
        print(f"\n✗ Error analyzing {result['domain']}: {result['error']}")
        return

    print("\n" + "="*70)
    print(f"DETAILED ANALYSIS: {result['domain']}")
    print("="*70)

    # SPF Details
    spf = result.get('spf', {})
    print(f"\n📧 SPF Configuration:")
    print(f"  • Has SPF:              {spf.get('has_spf', False)}")
    if spf.get('has_spf'):
        print(
            f"  • Record:               {spf.get('raw_record', 'N/A')}")
        print(f"  • DNS Lookups:          {spf.get('total_lookups', 0)}")
        print(f"  • Includes Count:       {spf.get('includes_count', 0)}")
        print(f"  • Policy Qualifier:     {spf.get('all_qualifier', 'NONE')}")
        permissive = spf.get('permissive_policy', False)
        print(
            f"  • Permissive Policy:    {permissive}")
        if permissive:
            print(f"    ℹ️  Permissive means SPF allows unauthorized senders:")
            print(
                f"       ~all (softfail), ?all (neutral), +all (pass), or no 'all' mechanism")
            print(
                f"       Recommended: Use -all (fail/hardfail) to strictly reject unauthorized mail")

        if spf.get('shadow_includes'):
            print(
                f"  ⚠️  Shadow Includes:    {', '.join(spf.get('shadow_includes', []))}")
        if spf.get('suspicious_includes'):
            print(
                f"  ⚠️  Suspicious Includes: {', '.join(spf.get('suspicious_includes', []))}")

    # DMARC Details
    dmarc = result.get('dmarc', {})
    print(f"\n🔒 DMARC Configuration:")
    print(f"  • Has DMARC:            {dmarc.get('has_dmarc', False)}")
    if dmarc.get('has_dmarc'):
        print(f"  • Record:               {dmarc.get('record', 'N/A')}")
        print(f"  • Policy:               {dmarc.get('policy', 'NONE')}")
        print(
            f"  • Subdomain Policy:     {dmarc.get('subdomain_policy', 'NONE')}")
        print(f"  • Percentage:           {dmarc.get('pct', 100)}%")
        print(
            f"  • RUA Reports:          {len(dmarc.get('rua_uris', []))} configured")
        print(
            f"  • RUF Reports:          {len(dmarc.get('ruf_uris', []))} configured")

    # Findings
    findings_data = result.get('findings', {})
    summary = findings_data.get('summary', {})

    print(f"\n🔍 Findings Summary:")
    print(f"  • Total Findings:       {summary.get('total_findings', 0)}")
    print(f"  • Critical:             {summary.get('critical', 0)}")
    print(f"  • High:                 {summary.get('high', 0)}")
    print(f"  • Medium:               {summary.get('medium', 0)}")
    print(f"  • Low:                  {summary.get('low', 0)}")
    print(f"  • Vulnerabilities:      {summary.get('vulnerabilities', 0)}")
    print(f"  • Attack Vectors:       {summary.get('attack_vectors', 0)}")
    print(
        f"  • Config Issues:        {summary.get('configuration_issues', 0)}")
    print(f"  • Compliance Issues:    {summary.get('compliance_issues', 0)}")

    # Detailed Findings
    findings_list = findings_data.get('findings', [])
    if findings_list:
        print(f"\n📋 Detailed Findings:")

        # Group by severity
        critical = [f for f in findings_list if f.get(
            'severity') == 'CRITICAL']
        high = [f for f in findings_list if f.get('severity') == 'HIGH']
        medium = [f for f in findings_list if f.get('severity') == 'MEDIUM']
        low = [f for f in findings_list if f.get('severity') == 'LOW']

        if critical:
            print(f"\n  🔴 CRITICAL ({len(critical)}):")
            for f in critical:
                print(f"    • {f.get('name')}: {f.get('description')}")
                if f.get('remediation'):
                    print(f"      ↳ Fix: {f.get('remediation')}")

        if high:
            print(f"\n  🟠 HIGH ({len(high)}):")
            for f in high:
                print(f"    • {f.get('name')}: {f.get('description')}")
                if f.get('remediation'):
                    print(f"      ↳ Fix: {f.get('remediation')}")

        if medium:
            print(f"\n  🟡 MEDIUM ({len(medium)}):")
            for f in medium:
                print(f"    • {f.get('name')}: {f.get('description')}")

        if low:
            print(f"\n  🟢 LOW ({len(low)}):")
            for f in low:
                print(f"    • {f.get('name')}: {f.get('description')}")

    # Attack Vectors
    attacks = result.get('attack_vectors', {})
    if attacks.get('attack_count', 0) > 0:
        print(f"\n⚔️  Attack Vector Analysis:")
        print(
            f"  • Is Attack Target:     {attacks.get('is_attack_target', False)}")
        print(
            f"  • Is Attack Source:     {attacks.get('is_attack_source', False)}")
        print(f"  • Detected Attacks:     {attacks.get('attack_count', 0)}")

        for attack in attacks.get('attacks', []):
            print(f"\n    • {attack.get('type')}")
            print(f"      Severity: {attack.get('severity')}")
            print(f"      {attack.get('description')}")
            if attack.get('mitigation'):
                print(f"      Mitigation: {attack.get('mitigation')}")

    print("\n" + "="*70)


def print_summary(results: List[Dict]):
    """
    Display summary of analysis results.

    Args:
        results: List of analysis results
    """
    if not results:
        print("\nNo results to display.")
        return

    total = len(results)

    # Statistiques générales
    with_spf = sum(1 for r in results if r.get(
        'spf', {}).get('has_spf', False))
    with_dmarc = sum(1 for r in results if r.get(
        'dmarc', {}).get('has_dmarc', False))
    with_both = sum(1 for r in results
                    if r.get('spf', {}).get('has_spf', False) and
                    r.get('dmarc', {}).get('has_dmarc', False))

    # Comptage par niveau de risque
    risk_stats = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0
    }

    # Severity and attack statistics
    critical_count = 0
    high_count = 0
    attack_targets = 0
    attack_sources = 0

    for result in results:
        if 'error' not in result:
            findings_data = result.get('findings', {})
            summary = findings_data.get('summary', {})

            critical_count += summary.get('critical', 0)
            high_count += summary.get('high', 0)

            attacks = result.get('attack_vectors', {})
            if attacks.get('is_attack_target', False):
                attack_targets += 1
            if attacks.get('is_attack_source', False):
                attack_sources += 1

    print("\n" + "="*70)
    print("ANALYSIS SUMMARY")
    print("="*70)

    print(f"\n📊 Domains analyzed: {total}")
    print(
        f"  • With SPF:          {with_spf:4} ({with_spf*100//total if total else 0}%)")
    print(
        f"  • With DMARC:        {with_dmarc:4} ({with_dmarc*100//total if total else 0}%)")
    print(
        f"  • With SPF + DMARC:  {with_both:4} ({with_both*100//total if total else 0}%)")

    print(f"\n⚠️  Critical Findings:")
    print(f"  • Critical severity:  {critical_count:4}")
    print(f"  • High severity:      {high_count:4}")
    print(
        f"  • Attack targets:     {attack_targets:4} ({attack_targets*100//total if total else 0}%)")
    print(
        f"  • Attack sources:     {attack_sources:4} ({attack_sources*100//total if total else 0}%)")

    # Top domains with critical findings
    domains_with_findings = [
        (r['domain'], r.get('findings', {}).get('summary', {}).get('critical', 0) +
         r.get('findings', {}).get('summary', {}).get('high', 0))
        for r in results if 'error' not in r
    ]

    critical_domains = [(d, f) for d, f in domains_with_findings if f > 0]

    if critical_domains:
        print(f"\n🚨 Top domains with critical/high findings:")
        sorted_critical = sorted(
            critical_domains, key=lambda x: x[1], reverse=True)[:10]

        for domain, finding_count in sorted_critical:
            print(f"  • {domain:30} [{finding_count:3} critical/high]")

    # Most frequent findings
    finding_counts = {}
    for r in results:
        if 'error' not in r:
            findings_list = r.get('findings', {}).get('findings', [])
            for f in findings_list:
                name = f.get('name', 'UNKNOWN')
                finding_counts[name] = finding_counts.get(name, 0) + 1

    if finding_counts:
        print(f"\n🔍 Most Frequent Findings:")
        sorted_findings = sorted(finding_counts.items(),
                                 key=lambda x: x[1], reverse=True)[:5]
        for finding, count in sorted_findings:
            pct = count * 100 // total if total else 0
            bar = '▓' * (count * 20 // max(finding_counts.values())
                         if max(finding_counts.values()) > 0 else 0)
            print(f"  {finding:30} {count:4} ({pct:3}%) {bar}")

    print("="*70 + "\n")


def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(
        description='SPF & DMARC Security Analyzer - Outil complet',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Analyser le top 100 de Tranco
  %(prog)s --tranco --top 100 --output results.csv
  
  # Analyser une liste de domaines
  %(prog)s --file domains.txt --output results.csv
  
  # Analyser un seul domaine avec détails
  %(prog)s --domain example.com --verbose
  
  # Export JSON avec mode verbeux
  %(prog)s --tranco --top 50 --format json --output results.json --verbose
  
  # Analyser avec focus sur les attaques
  %(prog)s --file suspicious_domains.txt --format json --output attacks.json

⚠️  RAPPEL ÉTHIQUE:
Cet outil est destiné à la recherche académique uniquement.
N'utilisez cet outil que dans un cadre légal et éthique.
        """
    )

    # Source des domaines
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        '--tranco',
        action='store_true',
        help='Utiliser la liste Tranco des domaines populaires'
    )
    source_group.add_argument(
        '--file',
        type=str,
        help='Fichier contenant une liste de domaines (un par ligne)'
    )
    source_group.add_argument(
        '--domain',
        type=str,
        help='Analyser un seul domaine'
    )

    # Options
    parser.add_argument(
        '--top',
        type=int,
        default=100,
        help='Nombre de domaines à récupérer depuis Tranco (défaut: 100)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='spf_dmarc_analysis.csv',
        help='Fichier de sortie (défaut: spf_dmarc_analysis.csv)'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['csv', 'json'],
        default='csv',
        help='Format de sortie (défaut: csv)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mode verbeux'
    )
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Ne pas afficher le résumé'
    )
    parser.add_argument(
        '--check-ip',
        type=str,
        help='IP address to check against SPF record (requires --domain)'
    )
    parser.add_argument(
        '--check-helo',
        type=str,
        help='HELO/EHLO hostname for SPF check (optional, defaults to domain)'
    )

    args = parser.parse_args()

    # Validate IP check arguments
    if args.check_ip and not args.domain:
        print("✗ Error: --check-ip requires --domain to be specified")
        sys.exit(1)

    # Handle IP check mode
    if args.check_ip:
        if not args.no_summary:
            print_banner()

        domain = args.domain
        ip = args.check_ip
        helo = args.check_helo if args.check_helo else domain

        print(f"\n{'='*70}")
        print(f"SPF & DMARC CHECK FOR IP: {ip}")
        print(f"{'='*70}")
        print(f"\n📧 Domain:      {domain}")
        print(f"🌐 IP Address:  {ip}")
        print(f"👋 HELO:        {helo}")
        print(f"\n{'='*70}")

        # Perform SPF check
        print(f"\n🔍 SPF Check:")
        spf_check = check_spf(domain, ip, helo)

        result_emoji = {
            'pass': '✅',
            'fail': '❌',
            'softfail': '⚠️',
            'neutral': '❔',
            'none': '🚫',
            'temperror': '⏱️',
            'permerror': '💥'
        }

        print(
            f"  Result:      {result_emoji.get(spf_check['result'], '❓')} {spf_check['result'].upper()}")
        if spf_check.get('mechanism'):
            print(f"  Mechanism:   {spf_check['mechanism']}")
        print(f"  Explanation: {spf_check['explanation']}")

        # Perform DMARC check
        print(f"\n🔒 DMARC Check:")
        dmarc_check = check_dmarc(domain, spf_check['result'], domain, helo)

        dmarc_emoji = {
            'pass': '✅',
            'fail': '❌',
            'none': '🚫'
        }

        print(
            f"  Result:      {dmarc_emoji.get(dmarc_check['result'], '❓')} {dmarc_check['result'].upper()}")
        if dmarc_check.get('record'):
            print(f"  Record:      {dmarc_check['record']}")
        if dmarc_check.get('policy'):
            print(f"  Policy:      {dmarc_check['policy']}")
        print(f"  SPF Aligned: {dmarc_check['spf_aligned']}")
        print(f"  Explanation: {dmarc_check['explanation']}")

        print(f"\n{'='*70}")
        print("\n💡 Summary:")

        if spf_check['result'] == 'pass' and dmarc_check['result'] == 'pass':
            print("  ✅ Email would likely be ACCEPTED by the receiving server")
        elif spf_check['result'] == 'fail' and dmarc_check['policy'] == 'reject':
            print("  ❌ Email would be REJECTED by the receiving server")
        elif spf_check['result'] == 'softfail' or dmarc_check['policy'] == 'quarantine':
            print("  ⚠️  Email would likely be marked as SPAM or QUARANTINED")
        else:
            print(f"  ℹ️  Email delivery depends on receiving server's policies")

        print(f"\n{'='*70}\n")
        sys.exit(0)

    # Afficher le banner
    if not args.no_summary:
        print_banner()

    # Récupérer les domaines à analyser
    domains = []

    if args.tranco:
        print(f"📡 Récupération de la liste Tranco (top {args.top})...")
        domains = fetch_tranco_list(args.top)
        if not domains:
            print("✗ Échec de la récupération de la liste Tranco.")
            print("  Conseil: Essayez avec --file pour charger une liste locale.")
            sys.exit(1)
    elif args.file:
        print(f"📂 Chargement des domaines depuis {args.file}...")
        domains = load_domains_from_file(args.file)
        if not domains:
            print(f"✗ Aucun domaine trouvé dans {args.file}")
            sys.exit(1)
    elif args.domain:
        domains = [args.domain]

    print(f"🎯 {len(domains)} domaine(s) à analyser\n")

    # Analyser tous les domaines
    results = []
    for i, domain in enumerate(domains, 1):
        if args.verbose:
            print(f"[{i}/{len(domains)}]", end=' ')

        result = analyze_domain(domain, verbose=args.verbose)
        results.append(result)

    # Display results based on number of domains
    if len(domains) == 1 and not args.no_summary:
        # Single domain: Show detailed analysis
        print_detailed_analysis(results[0])
    elif not args.no_summary:
        # Multiple domains: Show summary statistics
        print_summary(results)

    # Exporter les résultats
    output_path = "logs/csv/" + \
        args.output if args.format == 'csv' else "logs/json/" + args.output

    # Créer les répertoires si nécessaires
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if args.format == 'csv':
        export_to_csv(results, output_path)
    else:
        export_to_json(results, output_path)

    print(f"\n✅ Analysis complete!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Analyse interrompue par l'utilisateur.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

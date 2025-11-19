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

from tranco_fetcher import fetch_tranco_list, load_domains_from_file
from dmarc_analyzer import analyze_dmarc_security
from exploit_detector import ExploitDetector
from spf_analyzer import SPFAnalyzer
from attack_detector import AttackDetector
from risk_score import RiskScoreCalculator


def print_banner():
    """Affiche le banner du programme."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║      SPF & DMARC Security Analyzer - Comprehensive Tool      ║
║           Projet Académique - Recherche en Sécurité          ║
╚══════════════════════════════════════════════════════════════╝

Analyse complète: SPF + DMARC + Attack Detection + Risk Scoring
Basé sur: RFC 7208 (SPF), RFC 7489 (DMARC), USENIX Security 2023

⚠️  USAGE ÉTHIQUE UNIQUEMENT - Recherche académique supervisée
"""
    print(banner)


def analyze_domain(domain: str, verbose: bool = False) -> Dict:
    """
    Analyse complète d'un domaine: SPF + DMARC + Attaques + Risk Score.

    Args:
        domain: Nom de domaine à analyser
        verbose: Mode verbeux

    Returns:
        Résultats complets de l'analyse
    """
    if verbose:
        print(f"  Analyse de {domain}...", end=' ')

    try:
        # 1. Analyse SPF
        spf_analyzer = SPFAnalyzer()
        spf_result = spf_analyzer.analyze_domain(domain)

        # 2. Analyse DMARC
        dmarc_result = analyze_dmarc_security(domain)

        # 3. Détection des exploits DMARC (ancien système)
        dmarc_exploits = ExploitDetector.run_all_detectors(dmarc_result)

        # 4. Détection d'attaques ciblées (nouveau système)
        attack_analysis = AttackDetector.detect_targeted_attack(
            domain, spf_result, dmarc_result
        )

        # 5. Calcul du score de risque unifié
        unified_risk = RiskScoreCalculator.calculate_unified_score(
            domain, spf_result, dmarc_result, attack_analysis
        )

        # Construire le résultat complet
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),

            # SPF
            'spf': {
                'has_spf': spf_result.has_spf,
                'raw_record': spf_result.spf_record.raw_record if spf_result.spf_record else None,
                'total_lookups': spf_result.total_lookups,
                'includes_count': len(spf_result.all_includes),
                'includes': list(spf_result.all_includes),
                'shadow_includes': spf_result.shadow_includes,
                'suspicious_includes': spf_result.suspicious_includes,
                'vulnerabilities': spf_result.vulnerabilities,
                'risk_score': spf_result.risk_score,
                'risk_level': spf_result.risk_level,
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

            # Exploits DMARC
            'dmarc_exploits': dmarc_exploits,

            # Attaques ciblées
            'targeted_attacks': {
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
                        'cvss_score': attack.cvss_score,
                        'mitigation': attack.mitigation
                    }
                    for attack in attack_analysis.detected_attacks
                ],
                'threat_level': attack_analysis.threat_level,
                'recommendations': attack_analysis.recommendations
            },

            # Score de risque unifié
            'unified_risk': {
                'total_score': unified_risk.total_score,
                'risk_level': unified_risk.risk_level,
                'spf_score': unified_risk.spf_score,
                'dmarc_score': unified_risk.dmarc_score,
                'attack_score': unified_risk.attack_score,
                'compliance_score': unified_risk.compliance_score,
                'vulnerability_count': unified_risk.vulnerability_count,
                'is_vulnerable_to_spoofing': unified_risk.is_vulnerable_to_spoofing,
                'summary': unified_risk.summary,
                'critical_actions': unified_risk.critical_actions,
                'recommended_actions': unified_risk.recommended_actions,
                'risk_factors': [
                    {
                        'category': factor.category.value,
                        'name': factor.name,
                        'score': factor.score,
                        'severity': factor.severity,
                        'description': factor.description,
                        'remediation': factor.remediation
                    }
                    for factor in unified_risk.risk_factors
                ]
            }
        }

        if verbose:
            risk_level = unified_risk.risk_level
            score = unified_risk.total_score
            print(f"✓ [{risk_level}] Score: {score}/100")

        return result

    except Exception as e:
        if verbose:
            print(f"✗ Erreur: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def export_to_csv(results: List[Dict], output_file: str):
    """
    Export les résultats au format CSV.

    Args:
        results: Liste des résultats d'analyse
        output_file: Chemin du fichier de sortie
    """
    if not results:
        print("Aucun résultat à exporter.")
        return

    fieldnames = [
        'domain',
        'timestamp',
        # SPF
        'spf_present',
        'spf_risk_level',
        'spf_risk_score',
        'spf_lookups',
        'spf_includes_count',
        'spf_shadow_includes',
        'spf_policy',
        'spf_vulnerabilities',
        # DMARC
        'dmarc_present',
        'dmarc_policy',
        'dmarc_subdomain_policy',
        'dmarc_pct',
        'dmarc_rua_count',
        'dmarc_ruf_count',
        # Unified Risk
        'total_risk_score',
        'risk_level',
        'vulnerability_count',
        'is_vulnerable_to_spoofing',
        'is_attack_target',
        'is_attack_source',
        'attack_count',
        # Compliance
        'is_compliant',
        'critical_actions_count',
        'summary',
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
                    'error': result['error'],
                    'spf_present': False,
                    'dmarc_present': False,
                    'total_risk_score': 0,
                    'vulnerability_count': 0
                }
            else:
                spf = result.get('spf', {})
                dmarc = result.get('dmarc', {})
                attacks = result.get('targeted_attacks', {})
                unified = result.get('unified_risk', {})

                row = {
                    'domain': result['domain'],
                    'timestamp': result.get('timestamp', ''),
                    # SPF
                    'spf_present': spf.get('has_spf', False),
                    'spf_risk_level': spf.get('risk_level', 'UNKNOWN'),
                    'spf_risk_score': spf.get('risk_score', 0),
                    'spf_lookups': spf.get('total_lookups', 0),
                    'spf_includes_count': spf.get('includes_count', 0),
                    'spf_shadow_includes': ','.join(spf.get('shadow_includes', [])),
                    'spf_policy': spf.get('all_qualifier', 'NONE'),
                    'spf_vulnerabilities': ','.join(spf.get('vulnerabilities', [])),
                    # DMARC
                    'dmarc_present': dmarc.get('has_dmarc', False),
                    'dmarc_policy': dmarc.get('policy', 'NONE'),
                    'dmarc_subdomain_policy': dmarc.get('subdomain_policy', 'NONE'),
                    'dmarc_pct': dmarc.get('pct', 100),
                    'dmarc_rua_count': len(dmarc.get('rua_uris', [])),
                    'dmarc_ruf_count': len(dmarc.get('ruf_uris', [])),
                    # Unified Risk
                    'total_risk_score': unified.get('total_score', 0),
                    'risk_level': unified.get('risk_level', 'UNKNOWN'),
                    'vulnerability_count': unified.get('vulnerability_count', 0),
                    'is_vulnerable_to_spoofing': unified.get('is_vulnerable_to_spoofing', False),
                    'is_attack_target': attacks.get('is_attack_target', False),
                    'is_attack_source': attacks.get('is_attack_source', False),
                    'attack_count': attacks.get('attack_count', 0),
                    # Compliance
                    'is_compliant': unified.get('total_score', 100) < 25,
                    'critical_actions_count': len(unified.get('critical_actions', [])),
                    'summary': unified.get('summary', ''),
                    'error': ''
                }

            writer.writerow(row)

    print(f"✓ Résultats exportés vers {output_file}")


def export_to_json(results: List[Dict], output_file: str):
    """
    Export les résultats au format JSON.

    Args:
        results: Liste des résultats d'analyse
        output_file: Chemin du fichier de sortie
    """
    output = {
        'metadata': {
            'tool': 'SPF & DMARC Security Analyzer',
            'version': '2.0',
            'timestamp': datetime.now().isoformat(),
            'domain_count': len(results),
            'analysis_components': [
                'SPF Analysis',
                'DMARC Analysis',
                'Attack Detection',
                'Risk Scoring'
            ]
        },
        'results': results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"✓ Résultats exportés vers {output_file}")


def print_summary(results: List[Dict]):
    """
    Affiche un résumé des résultats.

    Args:
        results: Liste des résultats d'analyse
    """
    if not results:
        print("\nAucun résultat à afficher.")
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

    # Vulnérabilités
    vulnerable_to_spoofing = 0
    attack_targets = 0
    attack_sources = 0

    for result in results:
        unified = result.get('unified_risk', {})
        attacks = result.get('targeted_attacks', {})

        risk_level = unified.get('risk_level', 'UNKNOWN')
        risk_stats[risk_level] += 1

        if unified.get('is_vulnerable_to_spoofing', False):
            vulnerable_to_spoofing += 1

        if attacks.get('is_attack_target', False):
            attack_targets += 1

        if attacks.get('is_attack_source', False):
            attack_sources += 1

    print("\n" + "="*70)
    print("RÉSUMÉ DE L'ANALYSE")
    print("="*70)

    print(f"\n📊 Domaines analysés: {total}")
    print(
        f"  • Avec SPF:          {with_spf:4} ({with_spf*100//total if total else 0}%)")
    print(
        f"  • Avec DMARC:        {with_dmarc:4} ({with_dmarc*100//total if total else 0}%)")
    print(
        f"  • Avec SPF + DMARC:  {with_both:4} ({with_both*100//total if total else 0}%)")

    print(f"\n🎯 Niveaux de risque:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = risk_stats[level]
        if count > 0:
            pct = count * 100 // total if total else 0
            bar = '█' * (count * 30 // max(risk_stats.values())
                         if max(risk_stats.values()) > 0 else 0)
            print(f"  {level:10} [{count:4}] {pct:3}% {bar}")

    print(f"\n⚠️  Vulnérabilités critiques:")
    print(
        f"  • Vulnérables au spoofing:  {vulnerable_to_spoofing:4} ({vulnerable_to_spoofing*100//total if total else 0}%)")
    print(
        f"  • Cibles d'attaque:         {attack_targets:4} ({attack_targets*100//total if total else 0}%)")
    print(
        f"  • Sources potentielles:     {attack_sources:4} ({attack_sources*100//total if total else 0}%)")

    # Top domaines critiques
    critical_domains = [
        r for r in results
        if r.get('unified_risk', {}).get('risk_level') in ['CRITICAL', 'HIGH']
    ]

    if critical_domains:
        print(
            f"\n🚨 Top {min(10, len(critical_domains))} domaines à risque élevé:")
        sorted_critical = sorted(
            critical_domains,
            key=lambda x: x.get('unified_risk', {}).get('total_score', 0),
            reverse=True
        )[:10]

        for r in sorted_critical:
            domain = r['domain']
            unified = r.get('unified_risk', {})
            score = unified.get('total_score', 0)
            level = unified.get('risk_level', 'UNKNOWN')
            print(f"  • {domain:30} [{level:8}] Score: {score:3}/100")

            # Actions critiques
            critical_actions = unified.get('critical_actions', [])
            if critical_actions:
                print(f"    ⚠️  {critical_actions[0][:60]}...")

    # Vulnérabilités les plus fréquentes
    vuln_counts = {}
    for r in results:
        spf_vulns = r.get('spf', {}).get('vulnerabilities', [])
        for v in spf_vulns:
            vuln_counts[v] = vuln_counts.get(v, 0) + 1

    if vuln_counts:
        print(f"\n🔍 Vulnérabilités SPF les plus fréquentes:")
        sorted_vulns = sorted(vuln_counts.items(),
                              key=lambda x: x[1], reverse=True)[:5]
        for vuln, count in sorted_vulns:
            pct = count * 100 // total if total else 0
            bar = '▓' * (count * 20 // max(vuln_counts.values())
                         if max(vuln_counts.values()) > 0 else 0)
            print(f"  {vuln:30} {count:4} ({pct:3}%) {bar}")

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

    args = parser.parse_args()

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

    # Afficher le résumé
    if not args.no_summary:
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

    print(f"\n✅ Analyse terminée!")

    # Message pour un domaine unique
    if len(domains) == 1 and not args.no_summary:
        result = results[0]
        if 'error' not in result:
            print("\n" + "="*70)
            print("DÉTAILS DE L'ANALYSE")
            print("="*70)

            unified = result.get('unified_risk', {})
            print(f"\n{unified.get('summary', '')}")

            # Actions critiques
            critical_actions = unified.get('critical_actions', [])
            if critical_actions:
                print(f"\n⚠️  ACTIONS CRITIQUES REQUISES:")
                for action in critical_actions:
                    print(f"  • {action}")

            # Recommandations
            recommendations = unified.get('recommended_actions', [])
            if recommendations:
                print(f"\n💡 RECOMMANDATIONS:")
                for rec in recommendations[:5]:
                    print(f"  • {rec}")

            print("\n" + "="*70)


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

#!/usr/bin/env python3
"""
DMARC RUA/RUF Exploit Analyzer
Projet académique - Analyse des vulnérabilités DMARC

Basé sur la recherche USENIX Security 2023:
"Platforms in Everything: Analyzing DMARC Adoption and Security Issues"

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


def print_banner():
    """Affiche le banner du programme."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║           DMARC RUA/RUF Exploit Analyzer                     ║
║           Projet Académique - Recherche en Sécurité          ║
╚══════════════════════════════════════════════════════════════╝

Basé sur: USENIX Security 2023 - DMARC Security Analysis
Auteurs: Recherche académique encadrée

⚠️  USAGE ÉTHIQUE UNIQUEMENT - Recherche académique supervisée
"""
    print(banner)


def analyze_domain(domain: str, verbose: bool = False) -> Dict:
    """
    Analyse complète d'un domaine: DMARC + détection d'exploits.
    
    Args:
        domain: Nom de domaine à analyser
        verbose: Mode verbeux
    
    Returns:
        Résultats complets de l'analyse
    """
    if verbose:
        print(f"  Analyse de {domain}...", end=' ')
    
    try:
        # Analyse DMARC
        dmarc_analysis = analyze_dmarc_security(domain)
        
        # Détection des exploits
        exploit_results = ExploitDetector.run_all_detectors(dmarc_analysis)
        
        # Fusionner les résultats
        result = {
            **dmarc_analysis,
            'exploit_analysis': exploit_results
        }
        
        if verbose:
            risk_level = exploit_results['risk_level']
            vuln_count = exploit_results['vulnerability_count']
            print(f"✓ [{risk_level}] {vuln_count} vulnérabilités")
        
        return result
        
    except Exception as e:
        if verbose:
            print(f"✗ Erreur: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'has_dmarc': False
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
        'has_dmarc',
        'policy',
        'subdomain_policy',
        'pct',
        'rua_count',
        'ruf_count',
        'rua_uris',
        'ruf_uris',
        'vulnerability_count',
        'vulnerabilities',
        'risk_score',
        'risk_level',
        'external_reporting',
        'data_exfiltration',
        'amplification_potential',
        'forensic_abuse',
        'policy_bypass',
        'uri_manipulation'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            if 'error' in result:
                row = {
                    'domain': result['domain'],
                    'has_dmarc': False,
                    'vulnerability_count': 0
                }
            else:
                exploit_analysis = result.get('exploit_analysis', {})
                exploits = exploit_analysis.get('exploits', {})
                
                row = {
                    'domain': result['domain'],
                    'has_dmarc': result['has_dmarc'],
                    'policy': result.get('policy', ''),
                    'subdomain_policy': result.get('subdomain_policy', ''),
                    'pct': result.get('pct', 100),
                    'rua_count': len(result.get('rua_uris', [])),
                    'ruf_count': len(result.get('ruf_uris', [])),
                    'rua_uris': ';'.join(result.get('rua_uris', [])),
                    'ruf_uris': ';'.join(result.get('ruf_uris', [])),
                    'vulnerability_count': exploit_analysis.get('vulnerability_count', 0),
                    'vulnerabilities': ','.join(exploit_analysis.get('vulnerabilities', [])),
                    'risk_score': exploit_analysis.get('risk_score', 0),
                    'risk_level': exploit_analysis.get('risk_level', 'LOW'),
                    'external_reporting': exploits.get('external_reporting', {}).get('vulnerable', False),
                    'data_exfiltration': exploits.get('data_exfiltration', {}).get('vulnerable', False),
                    'amplification_potential': exploits.get('amplification', {}).get('vulnerable', False),
                    'forensic_abuse': exploits.get('forensic_abuse', {}).get('vulnerable', False),
                    'policy_bypass': exploits.get('policy_bypass', {}).get('vulnerable', False),
                    'uri_manipulation': exploits.get('uri_manipulation', {}).get('vulnerable', False)
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
            'tool': 'DMARC RUA/RUF Exploit Analyzer',
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'domain_count': len(results)
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
    with_dmarc = sum(1 for r in results if r.get('has_dmarc', False))
    without_dmarc = total - with_dmarc
    
    # Compter les vulnérabilités
    vuln_stats = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    exploit_types = {
        'external_reporting': 0,
        'data_exfiltration': 0,
        'amplification': 0,
        'forensic_abuse': 0,
        'policy_bypass': 0,
        'uri_manipulation': 0
    }
    
    for result in results:
        if 'exploit_analysis' in result:
            risk_level = result['exploit_analysis'].get('risk_level', 'LOW')
            vuln_stats[risk_level] += 1
            
            for vuln_name in result['exploit_analysis'].get('vulnerabilities', []):
                if vuln_name in exploit_types:
                    exploit_types[vuln_name] += 1
    
    print("\n" + "="*70)
    print("RÉSUMÉ DE L'ANALYSE")
    print("="*70)
    print(f"\nDomaines analysés: {total}")
    print(f"  - Avec DMARC:    {with_dmarc} ({with_dmarc*100//total if total else 0}%)")
    print(f"  - Sans DMARC:    {without_dmarc} ({without_dmarc*100//total if total else 0}%)")
    
    print(f"\nNiveaux de risque:")
    print(f"  - CRITICAL:  {vuln_stats['CRITICAL']}")
    print(f"  - HIGH:      {vuln_stats['HIGH']}")
    print(f"  - MEDIUM:    {vuln_stats['MEDIUM']}")
    print(f"  - LOW:       {vuln_stats['LOW']}")
    
    print(f"\nVulnérabilités détectées:")
    print(f"  - External Reporting:     {exploit_types['external_reporting']}")
    print(f"  - Data Exfiltration:      {exploit_types['data_exfiltration']}")
    print(f"  - Amplification Attack:   {exploit_types['amplification']}")
    print(f"  - Forensic Report Abuse:  {exploit_types['forensic_abuse']}")
    print(f"  - Policy Bypass:          {exploit_types['policy_bypass']}")
    print(f"  - URI Manipulation:       {exploit_types['uri_manipulation']}")
    print("="*70 + "\n")


def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(
        description='DMARC RUA/RUF Exploit Analyzer - Projet Académique',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Analyser le top 100 de Tranco
  %(prog)s --tranco --top 100 --output results.csv
  
  # Analyser une liste de domaines
  %(prog)s --file domains.txt --output results.csv
  
  # Analyser un seul domaine
  %(prog)s --domain example.com
  
  # Export JSON avec mode verbeux
  %(prog)s --tranco --top 50 --format json --output results.json --verbose

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
        default='dmarc_exploit_results.csv',
        help='Fichier de sortie (défaut: dmarc_exploit_results.csv)'
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
    if args.format == 'csv':
        export_to_csv(results, "logs/csv/" + args.output)
    else:
        export_to_json(results, "logs/json/" + args.output)

    print(f"\n✅ Analyse terminée!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Analyse interrompue par l'utilisateur.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Erreur fatale: {e}")
        sys.exit(1)

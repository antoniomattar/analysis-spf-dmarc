#!/usr/bin/env python3
"""
Visualisateur de résultats DMARC
Affiche les résultats d'analyse de manière formatée et lisible
"""

import csv
import json
import argparse
import sys


def print_header(text, char='='):
    """Affiche un en-tête formaté"""
    print(f"\n{char * 70}")
    print(f"{text:^70}")
    print(f"{char * 70}\n")


def visualize_csv(filepath):
    """Visualise les résultats d'un fichier CSV"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            results = list(reader)
        
        print_header("RÉSULTATS D'ANALYSE DMARC")
        
        # Statistiques globales
        total = len(results)
        with_dmarc = sum(1 for r in results if r['has_dmarc'] == 'True')
        
        print(f"📊 Statistiques Globales")
        print(f"  Total de domaines analysés: {total}")
        print(f"  Avec DMARC: {with_dmarc} ({with_dmarc*100//total if total else 0}%)")
        print(f"  Sans DMARC: {total - with_dmarc}")
        
        # Répartition par niveau de risque
        risk_counts = {}
        for r in results:
            level = r.get('risk_level', 'UNKNOWN')
            risk_counts[level] = risk_counts.get(level, 0) + 1
        
        print(f"\n📈 Répartition par niveau de risque:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = risk_counts.get(level, 0)
            if count > 0:
                bar = '█' * (count * 20 // max(risk_counts.values()) if risk_counts else 0)
                print(f"  {level:10} [{count:3}] {bar}")
        
        # Domaines à risque élevé
        high_risk = [r for r in results if r.get('risk_level') in ['CRITICAL', 'HIGH']]
        if high_risk:
            print_header("⚠️  DOMAINES À RISQUE ÉLEVÉ", '-')
            for r in high_risk:
                print(f"\n🔴 {r['domain']}")
                print(f"   Niveau: {r['risk_level']} (Score: {r['risk_score']})")
                print(f"   Politique: {r.get('policy', 'N/A')}")
                if r.get('vulnerabilities'):
                    vulns = r['vulnerabilities'].split(',')
                    print(f"   Vulnérabilités ({len(vulns)}):")
                    for v in vulns:
                        print(f"     • {v}")
                if r.get('rua_uris'):
                    print(f"   RUA: {r['rua_uris']}")
                if r.get('ruf_uris'):
                    print(f"   RUF: {r['ruf_uris']}")
        
        # Vulnérabilités les plus fréquentes
        vuln_counts = {}
        for r in results:
            if r.get('vulnerabilities'):
                for v in r['vulnerabilities'].split(','):
                    v = v.strip()
                    vuln_counts[v] = vuln_counts.get(v, 0) + 1
        
        if vuln_counts:
            print_header("🔍 VULNÉRABILITÉS LES PLUS FRÉQUENTES", '-')
            sorted_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
            for vuln, count in sorted_vulns:
                percentage = count * 100 // total if total else 0
                bar = '▓' * (count * 30 // max(vuln_counts.values()))
                print(f"  {vuln:30} {count:3} ({percentage:2}%) {bar}")
        
        # Domaines sûrs
        safe = [r for r in results if r.get('vulnerability_count') == '0']
        if safe:
            print_header(f"✅ DOMAINES SÛRS ({len(safe)})", '-')
            for r in safe[:10]:  # Afficher les 10 premiers
                print(f"  • {r['domain']:30} [{r.get('policy', 'N/A'):8}]")
            if len(safe) > 10:
                print(f"  ... et {len(safe) - 10} autres")
        
    except FileNotFoundError:
        print(f"❌ Erreur: Fichier {filepath} introuvable")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur lors de la lecture: {e}")
        sys.exit(1)


def visualize_json(filepath):
    """Visualise les résultats d'un fichier JSON"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print_header("RÉSULTATS D'ANALYSE DMARC")
        
        # Métadonnées
        metadata = data.get('metadata', {})
        print(f"📋 Métadonnées")
        print(f"  Outil: {metadata.get('tool', 'N/A')}")
        print(f"  Version: {metadata.get('version', 'N/A')}")
        print(f"  Date: {metadata.get('timestamp', 'N/A')}")
        print(f"  Domaines analysés: {metadata.get('domain_count', 0)}")
        
        results = data.get('results', [])
        
        # Domaines avec vulnérabilités critiques
        critical = [r for r in results 
                   if r.get('exploit_analysis', {}).get('risk_level') == 'CRITICAL']
        
        if critical:
            print_header("🚨 VULNÉRABILITÉS CRITIQUES", '-')
            for r in critical:
                exploit = r['exploit_analysis']
                print(f"\n🔴 {r['domain']}")
                print(f"   Score de risque: {exploit['risk_score']}/100")
                print(f"   Vulnérabilités: {exploit['vulnerability_count']}")
                
                for vuln_name in exploit.get('vulnerabilities', []):
                    vuln_detail = exploit['exploits'].get(vuln_name, {})
                    if vuln_detail.get('details'):
                        print(f"   • [{vuln_detail['severity']}] {vuln_detail['description']}")
                        print(f"     {vuln_detail['details']}")
        
        # Résumé des exploits
        print_header("📊 RÉSUMÉ DES EXPLOITS DÉTECTÉS", '-')
        exploit_summary = {}
        for r in results:
            for vuln in r.get('exploit_analysis', {}).get('vulnerabilities', []):
                exploit_summary[vuln] = exploit_summary.get(vuln, 0) + 1
        
        for exploit, count in sorted(exploit_summary.items(), key=lambda x: x[1], reverse=True):
            print(f"  {exploit:30} {count:3} domaines")
        
    except FileNotFoundError:
        print(f"❌ Erreur: Fichier {filepath} introuvable")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Erreur de parsing JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur lors de la lecture: {e}")
        sys.exit(1)


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description='Visualisateur de résultats DMARC',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'file',
        type=str,
        help='Fichier de résultats à visualiser (CSV ou JSON)'
    )
    parser.add_argument(
        '--format',
        choices=['csv', 'json', 'auto'],
        default='auto',
        help='Format du fichier (défaut: auto-détection)'
    )
    
    args = parser.parse_args()
    
    # Auto-détection du format
    if args.format == 'auto':
        if args.file.endswith('.json'):
            args.format = 'json'
        elif args.file.endswith('.csv'):
            args.format = 'csv'
        else:
            print("⚠️  Format non reconnu, tentative avec CSV...")
            args.format = 'csv'
    
    # Visualisation
    if args.format == 'csv':
        visualize_csv(args.file)
    else:
        visualize_json(args.file)
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Visualisation interrompue")
        sys.exit(1)

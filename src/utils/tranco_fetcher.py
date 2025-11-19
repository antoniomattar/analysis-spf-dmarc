#!/usr/bin/env python3
"""
Tranco List Fetcher - Récupère la liste Tranco des domaines populaires
Projet académique - Analyse des vulnérabilités DMARC RUA/RUF

Utilise la bibliothèque officielle Tranco pour un accès simplifié et fiable.
"""

from tranco import Tranco
from typing import List, Optional
import os


def fetch_tranco_list(top_n: int = 1000, list_id: Optional[str] = None, date: Optional[str] = None) -> List[str]:
    """
    Récupère les top N domaines de la liste Tranco en utilisant la bibliothèque officielle.
    
    Args:
        top_n: Nombre de domaines à récupérer
        list_id: ID spécifique de liste Tranco (optionnel)
        date: Date spécifique au format 'YYYY-MM-DD' (optionnel, utilise la dernière par défaut)
    
    Returns:
        Liste des noms de domaine
    """
    try:
        # Créer le répertoire de cache s'il n'existe pas
        cache_dir = ".tranco"
        os.makedirs(cache_dir, exist_ok=True)
        
        # Créer l'objet Tranco avec cache
        print(f"📡 Récupération de la liste Tranco (top {top_n})...")
        t = Tranco(cache=True, cache_dir=cache_dir)
        
        # Récupérer la liste appropriée
        if list_id:
            # Utiliser un ID spécifique
            tranco_list = t.list(list_id=list_id)
            print(f"   Liste ID: {list_id}")
        elif date:
            # Utiliser une date spécifique
            tranco_list = t.list(date=date)
            print(f"   Date: {date}")
        else:
            # Utiliser la liste la plus récente
            tranco_list = t.list()
            print(f"   Liste: la plus récente")
        
        # Récupérer les top N domaines
        domains = tranco_list.top(top_n)
        
        print(f"✓ {len(domains)} domaines récupérés avec succès")
        
        # Afficher quelques infos sur la liste
        if domains:
            print(f"   Exemples: {', '.join(domains[:3])}...")
        
        return domains
        
    except Exception as e:
        print(f"✗ Erreur lors de la récupération Tranco: {e}")
        print(f"   Conseil: Vérifiez votre connexion Internet")
        return []


def load_domains_from_file(filepath: str) -> List[str]:
    """
    Charge une liste de domaines depuis un fichier (un domaine par ligne ou CSV).
    
    Args:
        filepath: Chemin vers le fichier
    
    Returns:
        Liste des noms de domaine
    """
    domains = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Si CSV, prendre la première colonne
                if ',' in line:
                    domain = line.split(',')[0].strip()
                else:
                    domain = line.split()[0] if line.split() else ''
                
                if domain:
                    domains.append(domain)
        
        print(f"✓ {len(domains)} domaines chargés depuis {filepath}")
        return domains
        
    except Exception as e:
        print(f"✗ Erreur lors de la lecture du fichier: {e}")
        return []


if __name__ == '__main__':
    # Test rapide de la bibliothèque Tranco
    print("=== Test de la bibliothèque Tranco ===\n")
    
    # Test 1: Liste la plus récente
    print("Test 1: Top 10 de la liste la plus récente")
    domains = fetch_tranco_list(top_n=10)
    if domains:
        print("\nDomaines récupérés:")
        for i, d in enumerate(domains, 1):
            print(f"  {i:2}. {d}")
    
    # Test 2: Charger depuis un fichier
    print("\n" + "="*50)
    print("\nTest 2: Chargement depuis fichier")
    test_file = "test_domains.txt"
    if os.path.exists(test_file):
        file_domains = load_domains_from_file(test_file)
        if file_domains:
            print(f"\nDomaines du fichier: {', '.join(file_domains)}")
    else:
        print(f"   Fichier {test_file} non trouvé (normal pour le test)")

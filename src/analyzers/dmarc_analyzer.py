#!/usr/bin/env python3
"""
DMARC Analyzer - Parse et analyse les enregistrements DMARC
Focus sur les tags RUA/RUF et détection de configurations vulnérables
Projet académique basé sur recherche USENIX Security 2023
"""

import re
import dns.resolver
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


def query_txt_records(domain: str) -> List[str]:
    """Récupère les enregistrements TXT d'un domaine."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        return [b''.join(r.strings).decode() for r in answers]
    except Exception:
        return []


def get_dmarc_record(domain: str) -> Optional[str]:
    """
    Récupère l'enregistrement DMARC d'un domaine.
    
    Args:
        domain: Nom de domaine à interroger
    
    Returns:
        L'enregistrement DMARC ou None
    """
    txt_records = query_txt_records(f"_dmarc.{domain}")
    for record in txt_records:
        if record.lower().startswith('v=dmarc1'):
            return record
    return None


def parse_dmarc_record(record: str) -> Dict[str, str]:
    """
    Parse un enregistrement DMARC et retourne un dictionnaire de tags.
    
    Args:
        record: Enregistrement DMARC brut
    
    Returns:
        Dictionnaire tag -> valeur
    """
    if not record:
        return {}
    
    tags = {}
    # Séparer par ; et parser les paires tag=valeur
    parts = [p.strip() for p in record.split(';') if p.strip()]
    
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            tags[key.strip().lower()] = value.strip()
        else:
            # Tag sans valeur (comme v=dmarc1)
            tags[part.strip().lower()] = ''
    
    return tags


def extract_rua_uris(dmarc_tags: Dict[str, str]) -> List[str]:
    """
    Extrait les URIs RUA (Aggregate reports) d'un enregistrement DMARC.
    
    Args:
        dmarc_tags: Dictionnaire des tags DMARC
    
    Returns:
        Liste des URIs RUA
    """
    rua = dmarc_tags.get('rua', '')
    if not rua:
        return []
    
    # Les URIs sont séparés par des virgules
    uris = [uri.strip() for uri in rua.split(',') if uri.strip()]
    return uris


def extract_ruf_uris(dmarc_tags: Dict[str, str]) -> List[str]:
    """
    Extrait les URIs RUF (Forensic/Failure reports) d'un enregistrement DMARC.
    
    Args:
        dmarc_tags: Dictionnaire des tags DMARC
    
    Returns:
        Liste des URIs RUF
    """
    ruf = dmarc_tags.get('ruf', '')
    if not ruf:
        return []
    
    uris = [uri.strip() for uri in ruf.split(',') if uri.strip()]
    return uris


def extract_domain_from_uri(uri: str) -> Optional[str]:
    """
    Extrait le domaine d'une URI mailto: ou https:.
    
    Args:
        uri: URI à parser (ex: mailto:dmarc@example.com ou https://example.com/report)
    
    Returns:
        Nom de domaine ou None
    """
    try:
        if uri.startswith('mailto:'):
            # Format: mailto:user@domain.com ou mailto:user@domain.com!10m
            email_part = uri[7:].split('!')[0]  # Enlever les options (!10m, etc.)
            if '@' in email_part:
                return email_part.split('@')[1]
        elif uri.startswith('http://') or uri.startswith('https://'):
            parsed = urlparse(uri)
            return parsed.netloc
    except Exception:
        pass
    return None


def get_organizational_domain(domain: str) -> str:
    """
    Extrait le domaine organisationnel (eTLD+1) d'un FQDN.
    Simplification: prend les deux derniers composants.
    
    Args:
        domain: Nom de domaine complet
    
    Returns:
        Domaine organisationnel
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        # Gestion basique des TLDs composés (.co.uk, etc.)
        if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'gov', 'ac']:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain


def analyze_dmarc_security(domain: str) -> Dict:
    """
    Analyse complète de la sécurité DMARC d'un domaine.
    
    Args:
        domain: Nom de domaine à analyser
    
    Returns:
        Dictionnaire avec résultats d'analyse
    """
    result = {
        'domain': domain,
        'has_dmarc': False,
        'dmarc_record': None,
        'policy': None,
        'subdomain_policy': None,
        'pct': 100,
        'rua_uris': [],
        'ruf_uris': [],
        'rua_domains': [],
        'ruf_domains': [],
        'vulnerabilities': [],
        'risk_score': 0
    }
    
    # Récupérer l'enregistrement DMARC
    dmarc_record = get_dmarc_record(domain)
    if not dmarc_record:
        result['vulnerabilities'].append('NO_DMARC_RECORD')
        result['risk_score'] = 30
        return result
    
    result['has_dmarc'] = True
    result['dmarc_record'] = dmarc_record
    
    # Parser les tags
    tags = parse_dmarc_record(dmarc_record)
    
    # Politique
    result['policy'] = tags.get('p', 'none')
    result['subdomain_policy'] = tags.get('sp', result['policy'])
    
    # Pourcentage
    try:
        result['pct'] = int(tags.get('pct', '100'))
    except ValueError:
        result['pct'] = 100
    
    # Extraire RUA et RUF
    result['rua_uris'] = extract_rua_uris(tags)
    result['ruf_uris'] = extract_ruf_uris(tags)
    
    # Extraire les domaines des URIs
    result['rua_domains'] = [extract_domain_from_uri(uri) for uri in result['rua_uris']]
    result['rua_domains'] = [d for d in result['rua_domains'] if d]
    
    result['ruf_domains'] = [extract_domain_from_uri(uri) for uri in result['ruf_uris']]
    result['ruf_domains'] = [d for d in result['ruf_domains'] if d]
    
    return result


if __name__ == '__main__':
    # Test rapide
    test_domains = ['google.com', 'facebook.com', 'example.com']
    for domain in test_domains:
        print(f"\n=== Analyse de {domain} ===")
        result = analyze_dmarc_security(domain)
        print(f"DMARC présent: {result['has_dmarc']}")
        if result['has_dmarc']:
            print(f"Politique: {result['policy']}")
            print(f"RUA URIs: {result['rua_uris']}")
            print(f"RUF URIs: {result['ruf_uris']}")

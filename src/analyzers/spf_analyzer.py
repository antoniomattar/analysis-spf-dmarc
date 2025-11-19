#!/usr/bin/env python3
"""
SPF Analyzer - Analyse complète des enregistrements SPF
Détection de vulnérabilités, shadow includes, chaînes abusives, lookups excessifs

Fonctionnalités:
- Parsing récursif des includes/redirect
- Comptage des DNS lookups (RFC 7208 limite à 10)
- Détection de shadow includes (domaines compromis)
- Analyse des mécanismes permissifs (+all, ~all, ?all)
- Détection des PTR (déprécié et dangereux)
- Analyse de la complexité et du risque

Projet académique - Recherche en sécurité
"""

import re
import dns.resolver
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class SPFQualifier(Enum):
    """Qualificateurs SPF selon RFC 7208"""
    PASS = "+"      # Autorisé
    FAIL = "-"      # Interdit (hard fail)
    SOFTFAIL = "~"  # Suspect (soft fail)
    NEUTRAL = "?"   # Neutre


class SPFMechanism(Enum):
    """Mécanismes SPF"""
    ALL = "all"
    INCLUDE = "include"
    A = "a"
    MX = "mx"
    IP4 = "ip4"
    IP6 = "ip6"
    PTR = "ptr"         # Déprécié !
    EXISTS = "exists"
    REDIRECT = "redirect"


@dataclass
class SPFRecord:
    """Représente un enregistrement SPF parsé"""
    domain: str
    raw_record: str
    mechanisms: List[Tuple[SPFQualifier, SPFMechanism,
                           Optional[str]]] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    redirect: Optional[str] = None
    all_qualifier: Optional[SPFQualifier] = None
    dns_lookups: int = 0
    has_ptr: bool = False
    errors: List[str] = field(default_factory=list)


@dataclass
class SPFAnalysisResult:
    """Résultat complet de l'analyse SPF"""
    domain: str
    has_spf: bool
    spf_record: Optional[SPFRecord] = None
    total_lookups: int = 0
    lookup_chain: List[str] = field(default_factory=list)
    all_includes: Set[str] = field(default_factory=set)
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    shadow_includes: List[str] = field(default_factory=list)
    suspicious_includes: List[str] = field(default_factory=list)
    permissive_policy: bool = False
    errors: List[str] = field(default_factory=list)


class SPFAnalyzer:
    """Analyseur SPF avec détection de vulnérabilités"""

    # Services de mail connus et légitimes
    KNOWN_EMAIL_SERVICES = {
        'google.com', '_spf.google.com', 'amazonses.com', 'spf.protection.outlook.com',
        'sendgrid.net', 'mailgun.org', 'mailchimp.com', 'mandrill.com',
        '_spf.salesforce.com', 'spf.messagelabs.com', 'mail.zendesk.com',
        'servers.mcsv.net', 'mktomail.com', 'freshdesk.com', '_spf.elasticemail.com'
    }

    # TLDs et domaines compromis fréquents (à étendre)
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga',
                       '.cf', '.gq', '.xyz', '.top', '.bid'}

    def __init__(self, max_lookups: int = 10, max_recursion_depth: int = 5):
        """
        Initialise l'analyseur SPF.

        Args:
            max_lookups: Limite RFC 7208 (par défaut 10)
            max_recursion_depth: Profondeur maximale d'includes
        """
        self.max_lookups = max_lookups
        self.max_recursion_depth = max_recursion_depth
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 8
        self._visited_domains: Set[str] = set()
        self._lookup_count = 0

    def analyze_domain(self, domain: str) -> SPFAnalysisResult:
        """
        Analyse complète du SPF d'un domaine.

        Args:
            domain: Nom de domaine à analyser

        Returns:
            Résultat complet de l'analyse
        """
        # Réinitialiser les compteurs
        self._visited_domains = set()
        self._lookup_count = 0

        result = SPFAnalysisResult(domain=domain, has_spf=False)

        # Récupérer l'enregistrement SPF
        spf_text = self._get_spf_record(domain)
        if not spf_text:
            result.vulnerabilities.append("NO_SPF_RECORD")
            result.risk_score = 30
            result.risk_level = "MEDIUM"
            return result

        result.has_spf = True

        # Parser l'enregistrement
        spf_record = self._parse_spf_record(domain, spf_text)
        result.spf_record = spf_record

        # Analyser récursivement les includes
        self._analyze_includes_recursive(spf_record, result, depth=0)

        # Calculer le total des lookups
        result.total_lookups = self._lookup_count

        # Détecter les vulnérabilités
        self._detect_vulnerabilities(result)

        # Calculer le score de risque
        result.risk_score = self._calculate_risk_score(result)
        result.risk_level = self._get_risk_level(result.risk_score)

        return result

    def _get_spf_record(self, domain: str) -> Optional[str]:
        """Récupère l'enregistrement SPF d'un domaine."""
        try:
            answers = self.resolver.resolve(domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt = self._normalize_txt_rdata(rdata).strip()
                if txt.lower().startswith('v=spf1'):
                    return txt
        except Exception as e:
            pass
        return None

    def _normalize_txt_rdata(self, rdata) -> str:
        """Normalise un enregistrement TXT DNS."""
        try:
            chunks = []
            for part in rdata.strings:
                if isinstance(part, bytes):
                    chunks.append(part)
                else:
                    chunks.append(str(part).encode("utf-8"))
            return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            txt = rdata.to_text()
            if txt.startswith('"') and txt.endswith('"'):
                return txt[1:-1]
            return txt

    def _parse_spf_record(self, domain: str, spf_text: str) -> SPFRecord:
        """
        Parse un enregistrement SPF et extrait tous les mécanismes.

        Args:
            domain: Domaine associé
            spf_text: Texte de l'enregistrement SPF

        Returns:
            SPFRecord parsé
        """
        record = SPFRecord(domain=domain, raw_record=spf_text)

        # Supprimer v=spf1 et split sur les espaces
        parts = spf_text.split()[1:] if spf_text.split() else []

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Déterminer le qualificateur
            qualifier = SPFQualifier.PASS
            if part[0] in ['+', '-', '~', '?']:
                if part[0] == '+':
                    qualifier = SPFQualifier.PASS
                elif part[0] == '-':
                    qualifier = SPFQualifier.FAIL
                elif part[0] == '~':
                    qualifier = SPFQualifier.SOFTFAIL
                elif part[0] == '?':
                    qualifier = SPFQualifier.NEUTRAL
                part = part[1:]

            # Parser le mécanisme
            if part.startswith('include:'):
                include_domain = part[8:]
                record.includes.append(include_domain)
                record.mechanisms.append(
                    (qualifier, SPFMechanism.INCLUDE, include_domain))

            elif part.startswith('redirect='):
                record.redirect = part[9:]
                record.mechanisms.append(
                    (qualifier, SPFMechanism.REDIRECT, record.redirect))

            elif part.startswith('a'):
                value = part[2:] if part.startswith('a:') else None
                record.mechanisms.append((qualifier, SPFMechanism.A, value))

            elif part.startswith('mx'):
                value = part[3:] if part.startswith('mx:') else None
                record.mechanisms.append((qualifier, SPFMechanism.MX, value))

            elif part.startswith('ip4:'):
                record.mechanisms.append(
                    (qualifier, SPFMechanism.IP4, part[4:]))

            elif part.startswith('ip6:'):
                record.mechanisms.append(
                    (qualifier, SPFMechanism.IP6, part[4:]))

            elif part.startswith('ptr'):
                record.has_ptr = True
                value = part[4:] if part.startswith('ptr:') else None
                record.mechanisms.append((qualifier, SPFMechanism.PTR, value))

            elif part.startswith('exists:'):
                record.mechanisms.append(
                    (qualifier, SPFMechanism.EXISTS, part[7:]))

            elif part == 'all' or part.endswith('all'):
                record.all_qualifier = qualifier
                record.mechanisms.append((qualifier, SPFMechanism.ALL, None))

        return record

    def _analyze_includes_recursive(self, spf_record: SPFRecord,
                                    result: SPFAnalysisResult, depth: int):
        """
        Analyse récursivement les includes SPF.

        Args:
            spf_record: Enregistrement SPF à analyser
            result: Résultat à remplir
            depth: Profondeur actuelle de récursion
        """
        if depth > self.max_recursion_depth:
            result.errors.append(
                f"MAX_RECURSION_DEPTH_EXCEEDED: {spf_record.domain}")
            return

        # Éviter les boucles infinies
        if spf_record.domain in self._visited_domains:
            result.errors.append(f"CIRCULAR_REFERENCE: {spf_record.domain}")
            return

        self._visited_domains.add(spf_record.domain)
        result.lookup_chain.append(spf_record.domain)

        # Compter les lookups DNS pour ce domaine
        for qualifier, mechanism, value in spf_record.mechanisms:
            if mechanism in [SPFMechanism.INCLUDE, SPFMechanism.A,
                             SPFMechanism.MX, SPFMechanism.PTR, SPFMechanism.EXISTS]:
                self._lookup_count += 1

        # Analyser les includes
        for include_domain in spf_record.includes:
            result.all_includes.add(include_domain)

            # Vérifier si c'est un service connu ou suspect
            self._check_include_reputation(include_domain, result)

            # Récupérer et analyser l'include
            include_spf = self._get_spf_record(include_domain)
            if include_spf:
                include_record = self._parse_spf_record(
                    include_domain, include_spf)
                self._analyze_includes_recursive(
                    include_record, result, depth + 1)

        # Suivre les redirects
        if spf_record.redirect:
            redirect_spf = self._get_spf_record(spf_record.redirect)
            if redirect_spf:
                redirect_record = self._parse_spf_record(
                    spf_record.redirect, redirect_spf)
                self._analyze_includes_recursive(
                    redirect_record, result, depth + 1)

    def _check_include_reputation(self, include_domain: str, result: SPFAnalysisResult):
        """
        Vérifie la réputation d'un domaine inclus.

        Args:
            include_domain: Domaine à vérifier
            result: Résultat où ajouter les découvertes
        """
        # Vérifier si c'est un service connu
        is_known = any(
            known in include_domain for known in self.KNOWN_EMAIL_SERVICES)

        # Vérifier les TLDs suspects
        has_suspicious_tld = any(include_domain.endswith(tld)
                                 for tld in self.SUSPICIOUS_TLDS)

        if has_suspicious_tld and not is_known:
            result.suspicious_includes.append(include_domain)

        # Détecter les "shadow includes" potentiels
        # Un shadow include est un domaine qui n'a rien à voir avec le domaine principal
        main_domain = result.domain
        main_org = self._get_organizational_domain(main_domain)
        include_org = self._get_organizational_domain(include_domain)

        # Si les domaines organisationnels sont différents ET ce n'est pas un service connu
        if main_org != include_org and not is_known:
            # Vérifier si le domaine inclus existe et a un enregistrement MX valide
            if not self._domain_looks_legitimate(include_domain):
                result.shadow_includes.append(include_domain)

    def _get_organizational_domain(self, domain: str) -> str:
        """Extrait le domaine organisationnel (eTLD+1)."""
        parts = domain.split('.')
        if len(parts) >= 2:
            # Gestion basique des TLDs composés
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'gov', 'ac']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain

    def _domain_looks_legitimate(self, domain: str) -> bool:
        """
        Vérifie si un domaine a l'air légitime (MX, site web, etc.).

        Returns:
            True si le domaine semble légitime
        """
        try:
            # Vérifier l'existence d'enregistrements MX
            mx_records = self.resolver.resolve(domain, 'MX', lifetime=3)
            if mx_records:
                return True
        except Exception:
            pass

        try:
            # Vérifier l'existence d'enregistrements A
            a_records = self.resolver.resolve(domain, 'A', lifetime=3)
            if a_records:
                return True
        except Exception:
            pass

        return False

    def _detect_vulnerabilities(self, result: SPFAnalysisResult):
        """
        Détecte les vulnérabilités dans la configuration SPF.

        Args:
            result: Résultat à enrichir avec les vulnérabilités
        """
        spf = result.spf_record
        if not spf:
            return

        # 1. Lookups excessifs (RFC violation)
        if result.total_lookups > self.max_lookups:
            result.vulnerabilities.append("EXCESSIVE_DNS_LOOKUPS")

        # 2. Politique permissive
        if spf.all_qualifier in [SPFQualifier.PASS, SPFQualifier.SOFTFAIL, SPFQualifier.NEUTRAL]:
            result.vulnerabilities.append("PERMISSIVE_POLICY")
            result.permissive_policy = True

        # 3. +all (complètement ouvert - très dangereux)
        if spf.all_qualifier == SPFQualifier.PASS:
            result.vulnerabilities.append("PLUS_ALL_POLICY")

        # 4. Pas de mécanisme 'all' du tout
        if spf.all_qualifier is None:
            result.vulnerabilities.append("NO_ALL_MECHANISM")

        # 5. Utilisation de PTR (déprécié et lent)
        if spf.has_ptr:
            result.vulnerabilities.append("USES_PTR_MECHANISM")

        # 6. Shadow includes détectés
        if result.shadow_includes:
            result.vulnerabilities.append("SHADOW_INCLUDE_DETECTED")

        # 7. Includes suspects
        if result.suspicious_includes:
            result.vulnerabilities.append("SUSPICIOUS_INCLUDE_DETECTED")

        # 8. Chaîne d'includes trop longue
        if len(result.all_includes) > 5:
            result.vulnerabilities.append("EXCESSIVE_INCLUDE_CHAIN")

        # 9. Redirection vers domaine externe
        if spf.redirect:
            redirect_org = self._get_organizational_domain(spf.redirect)
            main_org = self._get_organizational_domain(result.domain)
            if redirect_org != main_org:
                result.vulnerabilities.append("EXTERNAL_REDIRECT")

    def _calculate_risk_score(self, result: SPFAnalysisResult) -> int:
        """
        Calcule un score de risque SPF (0-100).

        Args:
            result: Résultat d'analyse

        Returns:
            Score de risque (0=sûr, 100=très dangereux)
        """
        score = 0

        # Pas de SPF = risque moyen
        if not result.has_spf:
            return 30

        # Pondération des vulnérabilités
        vuln_weights = {
            "PLUS_ALL_POLICY": 40,
            "SHADOW_INCLUDE_DETECTED": 35,
            "NO_SPF_RECORD": 30,
            "PERMISSIVE_POLICY": 25,
            "EXCESSIVE_DNS_LOOKUPS": 20,
            "SUSPICIOUS_INCLUDE_DETECTED": 20,
            "NO_ALL_MECHANISM": 15,
            "EXTERNAL_REDIRECT": 15,
            "EXCESSIVE_INCLUDE_CHAIN": 10,
            "USES_PTR_MECHANISM": 10,
        }

        for vuln in result.vulnerabilities:
            score += vuln_weights.get(vuln, 5)

        # Bonus de risque pour les lookups excessifs
        if result.total_lookups > self.max_lookups:
            excess = result.total_lookups - self.max_lookups
            score += min(excess * 3, 20)

        return min(100, score)

    def _get_risk_level(self, risk_score: int) -> str:
        """Convertit un score en niveau de risque."""
        if risk_score >= 70:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"


# Fonction utilitaire pour analyse rapide
def analyze_spf(domain: str) -> SPFAnalysisResult:
    """
    Fonction raccourcie pour analyser le SPF d'un domaine.

    Args:
        domain: Nom de domaine

    Returns:
        Résultat d'analyse SPF
    """
    analyzer = SPFAnalyzer()
    return analyzer.analyze_domain(domain)


if __name__ == '__main__':
    # Tests rapides
    test_domains = ['google.com', 'facebook.com', 'example.com', 'github.com']

    print("="*70)
    print("SPF ANALYZER - Tests")
    print("="*70)

    for domain in test_domains:
        print(f"\n🔍 Analyse de {domain}")
        result = analyze_spf(domain)

        print(f"   SPF présent: {result.has_spf}")
        print(f"   DNS Lookups: {result.total_lookups}/{10}")
        print(f"   Includes: {len(result.all_includes)}")
        print(f"   Risk Score: {result.risk_score}/100 [{result.risk_level}]")

        if result.vulnerabilities:
            print(f"   Vulnérabilités ({len(result.vulnerabilities)}):")
            for vuln in result.vulnerabilities:
                print(f"     • {vuln}")

        if result.shadow_includes:
            print(f"   ⚠️  Shadow includes: {result.shadow_includes}")

        if result.spf_record:
            print(f"   Politique: {result.spf_record.all_qualifier}")

#!/usr/bin/env python3
"""
Attack Detector - Détection d'attaques ciblées via SPF/DMARC
Analyse les configurations pour identifier les domaines utilisés pour attaquer
ou les domaines vulnérables à l'exploitation

Types d'attaques détectées:
1. Shadow SPF Include - domaine compromis inclus dans SPF
2. DMARC Report Hijacking - rapports détournés vers attaquant
3. Spoofing Vulnerability - configuration permettant l'usurpation
4. Subdomain Takeover Risk - sous-domaines mal protégés
5. Email Bombing via RUF - abus des rapports forensiques
6. DNS Amplification - configuration permettant l'amplification

Projet académique - Recherche en sécurité
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class AttackType(Enum):
    """Types d'attaques détectables"""
    SHADOW_SPF = "shadow_spf_include"
    DMARC_HIJACKING = "dmarc_report_hijacking"
    SPOOFING_VULNERABLE = "spoofing_vulnerability"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover_risk"
    EMAIL_BOMBING = "email_bombing_via_ruf"
    DNS_AMPLIFICATION = "dns_amplification"
    POLICY_BYPASS = "policy_bypass_attack"
    DATA_EXFILTRATION = "data_exfiltration"


class AttackSeverity(Enum):
    """Niveaux de sévérité des attaques"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class AttackPattern:
    """Pattern d'attaque détecté"""
    attack_type: AttackType
    severity: AttackSeverity
    description: str
    evidence: List[str] = field(default_factory=list)
    indicators: Dict[str, any] = field(default_factory=dict)
    mitigation: str = ""
    cvss_score: float = 0.0


@dataclass
class TargetedAttackAnalysis:
    """Analyse complète des attaques ciblées"""
    domain: str
    is_attack_target: bool = False
    is_attack_source: bool = False
    detected_attacks: List[AttackPattern] = field(default_factory=list)
    attack_vectors: Set[str] = field(default_factory=set)
    overall_risk_score: int = 0
    threat_level: str = "LOW"
    recommendations: List[str] = field(default_factory=list)


class AttackDetector:
    """Détecteur d'attaques ciblées via SPF/DMARC"""

    # Domaines connus compromis (liste simplifiée - à étendre)
    KNOWN_COMPROMISED_DOMAINS = {
        # Cette liste devrait être maintenue à jour avec des sources de threat intelligence
    }

    # Patterns suspects dans les URIs
    SUSPICIOUS_PATTERNS = [
        'tempmail', 'throwaway', 'guerrilla', 'temp-mail',
        'fakeinbox', 'yopmail', '10minutemail', 'mailinator'
    ]

    # Services mail légitimes mais souvent abusés
    ABUSE_PRONE_SERVICES = {
        'mailgun.org', 'sendgrid.net', 'mailchimp.com'
    }

    @staticmethod
    def detect_shadow_spf_attack(spf_result, dmarc_result=None) -> Optional[AttackPattern]:
        """
        Détecte les attaques par Shadow SPF Include.

        Un attaquant insère son domaine (ou un domaine compromis) dans le SPF
        d'un domaine cible pour pouvoir envoyer des emails légitimes en son nom.

        Args:
            spf_result: Résultat de l'analyse SPF
            dmarc_result: Résultat de l'analyse DMARC (optionnel)

        Returns:
            AttackPattern si détecté, None sinon
        """
        if not spf_result.has_spf:
            return None

        # Vérifier les shadow includes
        if not spf_result.shadow_includes:
            return None

        severity = AttackSeverity.HIGH
        if dmarc_result and dmarc_result.get('policy') == 'none':
            severity = AttackSeverity.CRITICAL

        evidence = [
            f"Shadow include detected: {inc}" for inc in spf_result.shadow_includes
        ]

        # Calculer CVSS (simplifié)
        cvss = 7.5 if severity == AttackSeverity.CRITICAL else 6.0

        return AttackPattern(
            attack_type=AttackType.SHADOW_SPF,
            severity=severity,
            description="Domaine(s) suspect(s) inclus dans SPF - possible compromission",
            evidence=evidence,
            indicators={
                'shadow_domains': spf_result.shadow_includes,
                'total_includes': len(spf_result.all_includes),
                'lookup_count': spf_result.total_lookups
            },
            mitigation=(
                "1. Vérifier la légitimité de chaque domaine inclus\n"
                "2. Supprimer les includes non nécessaires\n"
                "3. Implémenter DMARC avec policy=reject\n"
                "4. Monitorer les rapports DMARC pour détecter l'abus"
            ),
            cvss_score=cvss
        )

    @staticmethod
    def detect_dmarc_hijacking(dmarc_result, spf_result=None) -> Optional[AttackPattern]:
        """
        Détecte le détournement de rapports DMARC.

        Un attaquant configure des URIs RUA/RUF pour recevoir les rapports
        DMARC d'un domaine qu'il ne contrôle pas.

        Args:
            dmarc_result: Résultat de l'analyse DMARC
            spf_result: Résultat de l'analyse SPF (optionnel)

        Returns:
            AttackPattern si détecté, None sinon
        """
        if not dmarc_result.get('has_dmarc'):
            return None

        rua_domains = dmarc_result.get('rua_domains', [])
        ruf_domains = dmarc_result.get('ruf_domains', [])
        domain = dmarc_result['domain']

        # Extraire le domaine organisationnel
        main_org = AttackDetector._get_org_domain(domain)

        # Vérifier les domaines externes
        external_rua = [
            d for d in rua_domains if AttackDetector._get_org_domain(d) != main_org]
        external_ruf = [
            d for d in ruf_domains if AttackDetector._get_org_domain(d) != main_org]

        if not (external_rua or external_ruf):
            return None

        severity = AttackSeverity.CRITICAL if external_ruf else AttackSeverity.HIGH

        evidence = []
        if external_rua:
            evidence.extend([f"External RUA: {d}" for d in external_rua])
        if external_ruf:
            evidence.extend([f"External RUF: {d}" for d in external_ruf])

        # RUF est plus grave car contient des données sensibles
        cvss = 8.5 if external_ruf else 6.5

        return AttackPattern(
            attack_type=AttackType.DMARC_HIJACKING,
            severity=severity,
            description="Rapports DMARC envoyés à des domaines externes",
            evidence=evidence,
            indicators={
                'external_rua': external_rua,
                'external_ruf': external_ruf,
                'has_forensic': bool(external_ruf),
                'policy': dmarc_result.get('policy')
            },
            mitigation=(
                "1. Vérifier que les URIs externes sont autorisés (RFC 7489)\n"
                "2. Supprimer les URIs RUF si non nécessaires\n"
                "3. Valider les domaines externes via enregistrement TXT\n"
                "4. Utiliser uniquement des URIs de confiance"
            ),
            cvss_score=cvss
        )

    @staticmethod
    def detect_spoofing_vulnerability(spf_result, dmarc_result) -> Optional[AttackPattern]:
        """
        Détecte les vulnérabilités permettant l'usurpation d'email.

        Combinaison de SPF permissif + DMARC faible = facile à usurper.

        Args:
            spf_result: Résultat de l'analyse SPF
            dmarc_result: Résultat de l'analyse DMARC

        Returns:
            AttackPattern si vulnérable, None sinon
        """
        # Vérifier les conditions de vulnérabilité
        spf_weak = False
        dmarc_weak = False

        # SPF faible
        if not spf_result.has_spf:
            spf_weak = True
        elif spf_result.permissive_policy:
            spf_weak = True

        # DMARC faible
        if not dmarc_result.get('has_dmarc'):
            dmarc_weak = True
        elif dmarc_result.get('policy') in ['none', None]:
            dmarc_weak = True

        if not (spf_weak and dmarc_weak):
            return None

        # Calculer la sévérité
        if not spf_result.has_spf and not dmarc_result.get('has_dmarc'):
            severity = AttackSeverity.CRITICAL
        else:
            severity = AttackSeverity.HIGH

        evidence = []
        if not spf_result.has_spf:
            evidence.append("No SPF record")
        elif spf_result.permissive_policy:
            evidence.append(
                f"Permissive SPF: {spf_result.spf_record.all_qualifier}")

        if not dmarc_result.get('has_dmarc'):
            evidence.append("No DMARC record")
        elif dmarc_result.get('policy') == 'none':
            evidence.append("DMARC policy: none")

        return AttackPattern(
            attack_type=AttackType.SPOOFING_VULNERABLE,
            severity=severity,
            description="Domaine vulnérable à l'usurpation d'email (spoofing)",
            evidence=evidence,
            indicators={
                'spf_present': spf_result.has_spf,
                'spf_permissive': spf_result.permissive_policy,
                'dmarc_present': dmarc_result.get('has_dmarc'),
                'dmarc_policy': dmarc_result.get('policy'),
                'exploitability': 'HIGH'
            },
            mitigation=(
                "1. Implémenter un SPF strict avec -all\n"
                "2. Configurer DMARC avec policy=reject\n"
                "3. Activer DKIM sur tous les serveurs mail sortants\n"
                "4. Monitorer les rapports DMARC régulièrement"
            ),
            cvss_score=8.0 if severity == AttackSeverity.CRITICAL else 7.0
        )

    @staticmethod
    def detect_subdomain_takeover_risk(domain: str, spf_result, dmarc_result) -> Optional[AttackPattern]:
        """
        Détecte les risques de prise de contrôle de sous-domaines.

        Si le domaine parent a DMARC mais sp=none, les sous-domaines
        peuvent être exploités sans protection.

        Args:
            domain: Domaine analysé
            spf_result: Résultat SPF
            dmarc_result: Résultat DMARC

        Returns:
            AttackPattern si risque détecté, None sinon
        """
        if not dmarc_result.get('has_dmarc'):
            return None

        policy = dmarc_result.get('policy')
        sp_policy = dmarc_result.get('subdomain_policy', policy)

        # Risque si la politique principale est forte mais sp est faible
        parent_strong = policy in ['quarantine', 'reject']
        subdomain_weak = sp_policy in ['none', None]

        if not (parent_strong and subdomain_weak):
            return None

        return AttackPattern(
            attack_type=AttackType.SUBDOMAIN_TAKEOVER,
            severity=AttackSeverity.MEDIUM,
            description="Sous-domaines moins protégés que le domaine parent",
            evidence=[
                f"Parent policy: {policy}",
                f"Subdomain policy: {sp_policy}",
                "Subdomains vulnerable to takeover and spoofing"
            ],
            indicators={
                'parent_policy': policy,
                'subdomain_policy': sp_policy,
                'risk_level': 'MEDIUM'
            },
            mitigation=(
                "1. Configurer sp=reject ou sp=quarantine dans DMARC\n"
                "2. Auditer tous les sous-domaines actifs\n"
                "3. Supprimer les enregistrements DNS inutilisés\n"
                "4. Implémenter SPF pour chaque sous-domaine utilisé"
            ),
            cvss_score=5.5
        )

    @staticmethod
    def detect_email_bombing(dmarc_result) -> Optional[AttackPattern]:
        """
        Détecte le potentiel d'attaque par email bombing via RUF.

        Un attaquant peut déclencher l'envoi massif de rapports forensiques
        vers une cible en usurpant des emails.

        Args:
            dmarc_result: Résultat DMARC

        Returns:
            AttackPattern si vulnérable, None sinon
        """
        if not dmarc_result.get('has_dmarc'):
            return None

        ruf_uris = dmarc_result.get('ruf_uris', [])
        policy = dmarc_result.get('policy')

        # RUF avec policy=none = potentiel d'abus
        if not ruf_uris or policy not in ['none', None]:
            return None

        # Vérifier si les URIs sont vers des services vulnérables
        vulnerable_targets = [
            uri for uri in ruf_uris
            if any(pattern in uri.lower() for pattern in AttackDetector.SUSPICIOUS_PATTERNS)
        ]

        severity = AttackSeverity.HIGH if vulnerable_targets else AttackSeverity.MEDIUM

        return AttackPattern(
            attack_type=AttackType.EMAIL_BOMBING,
            severity=severity,
            description="Configuration permettant l'email bombing via RUF",
            evidence=[
                f"RUF URIs configured: {len(ruf_uris)}",
                f"Policy: {policy}",
                "Attacker can trigger forensic reports"
            ],
            indicators={
                'ruf_count': len(ruf_uris),
                'policy': policy,
                'vulnerable_targets': vulnerable_targets,
                'amplification_factor': len(ruf_uris) * 10
            },
            mitigation=(
                "1. Désactiver RUF si non nécessaire\n"
                "2. Implémenter un policy strict (reject)\n"
                "3. Limiter le pct à 1% pour tester\n"
                "4. Utiliser un service de collecte de rapports sécurisé"
            ),
            cvss_score=6.5
        )

    @staticmethod
    def detect_dns_amplification(spf_result, dmarc_result) -> Optional[AttackPattern]:
        """
        Détecte le potentiel d'attaque par amplification DNS.

        SPF avec beaucoup de lookups + DMARC avec reporting = amplification.

        Args:
            spf_result: Résultat SPF
            dmarc_result: Résultat DMARC

        Returns:
            AttackPattern si vulnérable, None sinon
        """
        if not spf_result.has_spf:
            return None

        excessive_lookups = spf_result.total_lookups > 10
        has_reporting = (dmarc_result.get('rua_uris')
                         or dmarc_result.get('ruf_uris'))

        if not (excessive_lookups and has_reporting):
            return None

        amplification_factor = spf_result.total_lookups * \
            len(dmarc_result.get('rua_uris', []))

        return AttackPattern(
            attack_type=AttackType.DNS_AMPLIFICATION,
            severity=AttackSeverity.MEDIUM,
            description="Configuration permettant l'amplification DNS",
            evidence=[
                f"DNS lookups: {spf_result.total_lookups}",
                f"RUA destinations: {len(dmarc_result.get('rua_uris', []))}",
                f"Amplification factor: {amplification_factor}x"
            ],
            indicators={
                'lookup_count': spf_result.total_lookups,
                'amplification_factor': amplification_factor,
                'attack_surface': 'HIGH'
            },
            mitigation=(
                "1. Réduire le nombre de lookups SPF sous 10\n"
                "2. Consolider les includes\n"
                "3. Utiliser ip4/ip6 au lieu d'includes quand possible\n"
                "4. Limiter le nombre de destinations RUA"
            ),
            cvss_score=5.0
        )

    @staticmethod
    def detect_targeted_attack(domain: str, spf_result, dmarc_result) -> TargetedAttackAnalysis:
        """
        Analyse complète pour détecter si un domaine est:
        - Cible d'une attaque
        - Source potentielle d'attaque
        - Vulnérable à l'exploitation

        Args:
            domain: Domaine à analyser
            spf_result: Résultat de l'analyse SPF
            dmarc_result: Résultat de l'analyse DMARC

        Returns:
            Analyse complète des attaques ciblées
        """
        analysis = TargetedAttackAnalysis(domain=domain)

        # Exécuter tous les détecteurs
        detectors = [
            AttackDetector.detect_shadow_spf_attack(spf_result, dmarc_result),
            AttackDetector.detect_dmarc_hijacking(dmarc_result, spf_result),
            AttackDetector.detect_spoofing_vulnerability(
                spf_result, dmarc_result),
            AttackDetector.detect_subdomain_takeover_risk(
                domain, spf_result, dmarc_result),
            AttackDetector.detect_email_bombing(dmarc_result),
            AttackDetector.detect_dns_amplification(spf_result, dmarc_result)
        ]

        # Filtrer les None et ajouter les patterns détectés
        for pattern in detectors:
            if pattern:
                analysis.detected_attacks.append(pattern)
                analysis.attack_vectors.add(pattern.attack_type.value)

        # Déterminer si c'est une cible ou une source d'attaque
        for attack in analysis.detected_attacks:
            if attack.attack_type in [AttackType.SHADOW_SPF, AttackType.DMARC_HIJACKING]:
                analysis.is_attack_target = True
            if attack.attack_type in [AttackType.SPOOFING_VULNERABLE, AttackType.EMAIL_BOMBING]:
                analysis.is_attack_source = True

        # Calculer le score de risque global
        analysis.overall_risk_score = AttackDetector._calculate_attack_risk_score(
            analysis.detected_attacks
        )
        analysis.threat_level = AttackDetector._get_threat_level(
            analysis.overall_risk_score)

        # Générer les recommandations
        analysis.recommendations = AttackDetector._generate_recommendations(
            analysis)

        return analysis

    @staticmethod
    def _calculate_attack_risk_score(attacks: List[AttackPattern]) -> int:
        """Calcule un score de risque global basé sur les attaques détectées."""
        if not attacks:
            return 0

        # Somme pondérée des sévérités
        severity_weights = {
            AttackSeverity.CRITICAL: 30,
            AttackSeverity.HIGH: 20,
            AttackSeverity.MEDIUM: 10,
            AttackSeverity.LOW: 5,
            AttackSeverity.INFO: 1
        }

        score = sum(severity_weights[attack.severity] for attack in attacks)

        # Bonus si multiples vecteurs d'attaque
        unique_types = len(set(attack.attack_type for attack in attacks))
        if unique_types > 2:
            score += 15

        return min(100, score)

    @staticmethod
    def _get_threat_level(risk_score: int) -> str:
        """Convertit un score en niveau de menace."""
        if risk_score >= 75:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _generate_recommendations(analysis: TargetedAttackAnalysis) -> List[str]:
        """Génère des recommandations basées sur les attaques détectées."""
        recommendations = []

        attack_types = {
            attack.attack_type for attack in analysis.detected_attacks}

        if AttackType.SHADOW_SPF in attack_types:
            recommendations.append(
                "Auditer tous les domaines inclus dans SPF et supprimer les suspects"
            )

        if AttackType.DMARC_HIJACKING in attack_types:
            recommendations.append(
                "Vérifier les URIs RUA/RUF et supprimer les domaines externes non autorisés"
            )

        if AttackType.SPOOFING_VULNERABLE in attack_types:
            recommendations.append(
                "Implémenter SPF strict (-all) et DMARC avec policy=reject immédiatement"
            )

        if AttackType.SUBDOMAIN_TAKEOVER in attack_types:
            recommendations.append(
                "Configurer sp=reject dans DMARC pour protéger les sous-domaines"
            )

        if AttackType.EMAIL_BOMBING in attack_types:
            recommendations.append(
                "Désactiver RUF ou implémenter un policy strict"
            )

        if AttackType.DNS_AMPLIFICATION in attack_types:
            recommendations.append(
                "Réduire le nombre de DNS lookups SPF sous la limite RFC (10)"
            )

        # Recommandations générales
        if analysis.overall_risk_score > 50:
            recommendations.append(
                "Effectuer un audit de sécurité complet de l'infrastructure mail"
            )

        return recommendations

    @staticmethod
    def _get_org_domain(domain: str) -> str:
        """Extrait le domaine organisationnel."""
        parts = domain.split('.')
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'gov', 'ac']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain


if __name__ == '__main__':
    # Tests d'exemple
    print("="*70)
    print("ATTACK DETECTOR - Tests")
    print("="*70)

    # Import local pour tests
    from spf_analyzer import analyze_spf
    from dmarc_analyzer import analyze_dmarc_security

    test_domains = ['example.com', 'google.com']

    for domain in test_domains:
        print(f"\n🎯 Analyse d'attaques pour {domain}")

        spf_result = analyze_spf(domain)
        dmarc_result = analyze_dmarc_security(domain)

        analysis = AttackDetector.detect_targeted_attack(
            domain, spf_result, dmarc_result)

        print(f"   Threat Level: {analysis.threat_level}")
        print(f"   Risk Score: {analysis.overall_risk_score}/100")
        print(f"   Is Attack Target: {analysis.is_attack_target}")
        print(f"   Is Attack Source: {analysis.is_attack_source}")

        if analysis.detected_attacks:
            print(
                f"\n   Attaques détectées ({len(analysis.detected_attacks)}):")
            for attack in analysis.detected_attacks:
                print(
                    f"     [{attack.severity.name}] {attack.attack_type.value}")
                print(f"       {attack.description}")

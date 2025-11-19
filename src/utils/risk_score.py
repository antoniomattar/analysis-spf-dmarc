#!/usr/bin/env python3
"""
Risk Score Module - Calcul unifié du score de risque SPF/DMARC
Combine les résultats d'analyse SPF, DMARC et détection d'attaques
pour produire un score de risque global et des recommandations

Scoring basé sur:
- Présence et qualité des enregistrements SPF/DMARC
- Vulnérabilités détectées
- Patterns d'attaque identifiés
- Conformité aux RFCs et best practices

Échelle de risque: 0-100
- 0-24: LOW (Sécurisé)
- 25-49: MEDIUM (Amélioration recommandée)
- 50-74: HIGH (Action requise)
- 75-100: CRITICAL (Action immédiate requise)

Projet académique - Recherche en sécurité
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class RiskCategory(Enum):
    """Catégories de risque"""
    CONFIGURATION = "configuration"
    SPOOFING = "spoofing"
    DATA_LEAKAGE = "data_leakage"
    ABUSE = "abuse"
    COMPLIANCE = "compliance"


@dataclass
class RiskFactor:
    """Facteur de risque individuel"""
    category: RiskCategory
    name: str
    score: int  # Contribution au score total
    severity: str
    description: str
    remediation: str


@dataclass
class UnifiedRiskScore:
    """Score de risque unifié pour un domaine"""
    domain: str
    total_score: int = 0  # 0-100
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL

    # Scores par composant
    spf_score: int = 0
    dmarc_score: int = 0
    attack_score: int = 0
    compliance_score: int = 0    # Facteurs de risque détaillés
    risk_factors: List[RiskFactor] = field(default_factory=list)

    # Métriques
    vulnerability_count: int = 0
    attack_vector_count: int = 0

    # État global
    has_spf: bool = False
    has_dmarc: bool = False
    is_compliant: bool = False
    is_vulnerable_to_spoofing: bool = False

    # Recommandations prioritaires
    critical_actions: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    # Détails supplémentaires
    summary: str = ""


class RiskScoreCalculator:
    """Calculateur de score de risque unifié"""

    # Poids des différentes composantes dans le score total
    WEIGHTS = {
        'spf': 0.30,      # 30% du score total
        'dmarc': 0.30,    # 30% du score total
        'attack': 0.30,   # 30% du score total
        'compliance': 0.10  # 10% du score total
    }

    @staticmethod
    def calculate_unified_score(domain: str,
                                spf_result=None,
                                dmarc_result=None,
                                attack_analysis=None) -> UnifiedRiskScore:
        """
        Calcule un score de risque unifié.

        Args:
            domain: Nom de domaine
            spf_result: Résultat de l'analyse SPF (SPFAnalysisResult)
            dmarc_result: Résultat de l'analyse DMARC (dict)
            attack_analysis: Résultat de l'analyse d'attaques (TargetedAttackAnalysis)

        Returns:
            Score de risque unifié
        """
        risk_score = UnifiedRiskScore(domain=domain, total_score=0)

        # Calculer les scores individuels
        spf_score, spf_factors = RiskScoreCalculator._calculate_spf_score(
            spf_result)
        dmarc_score, dmarc_factors = RiskScoreCalculator._calculate_dmarc_score(
            dmarc_result)
        attack_score, attack_factors = RiskScoreCalculator._calculate_attack_score(
            attack_analysis)
        compliance_score, compliance_factors = RiskScoreCalculator._calculate_compliance_score(
            spf_result, dmarc_result
        )

        # Stocker les scores
        risk_score.spf_score = spf_score
        risk_score.dmarc_score = dmarc_score
        risk_score.attack_score = attack_score
        risk_score.compliance_score = compliance_score

        # Calculer le score total pondéré
        risk_score.total_score = int(
            spf_score * RiskScoreCalculator.WEIGHTS['spf'] +
            dmarc_score * RiskScoreCalculator.WEIGHTS['dmarc'] +
            attack_score * RiskScoreCalculator.WEIGHTS['attack'] +
            compliance_score * RiskScoreCalculator.WEIGHTS['compliance']
        )

        # Déterminer le niveau de risque
        risk_score.risk_level = RiskScoreCalculator._get_risk_level(
            risk_score.total_score)

        # Combiner tous les facteurs de risque
        risk_score.risk_factors.extend(spf_factors)
        risk_score.risk_factors.extend(dmarc_factors)
        risk_score.risk_factors.extend(attack_factors)
        risk_score.risk_factors.extend(compliance_factors)

        # Trier par sévérité
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        risk_score.risk_factors.sort(
            key=lambda x: severity_order.get(x.severity, 4))

        # Métriques
        risk_score.vulnerability_count = len([f for f in risk_score.risk_factors
                                             if f.severity in ['CRITICAL', 'HIGH']])
        risk_score.attack_vector_count = len([f for f in risk_score.risk_factors
                                             if f.category == RiskCategory.ABUSE])

        # État global
        risk_score.has_spf = spf_result.has_spf if spf_result else False
        risk_score.has_dmarc = dmarc_result.get(
            'has_dmarc', False) if dmarc_result else False
        risk_score.is_compliant = compliance_score < 25
        risk_score.is_vulnerable_to_spoofing = RiskScoreCalculator._check_spoofing_vulnerability(
            spf_result, dmarc_result
        )

        # Générer les recommandations
        risk_score.critical_actions = RiskScoreCalculator._generate_critical_actions(
            risk_score)
        risk_score.recommended_actions = RiskScoreCalculator._generate_recommendations(
            risk_score)

        # Générer le résumé
        risk_score.summary = RiskScoreCalculator._generate_summary(risk_score)

        return risk_score

    @staticmethod
    def _calculate_spf_score(spf_result) -> Tuple[int, List[RiskFactor]]:
        """Calcule le score de risque SPF."""
        if not spf_result:
            return 100, [RiskFactor(
                category=RiskCategory.CONFIGURATION,
                name="NO_SPF_ANALYSIS",
                score=100,
                severity="CRITICAL",
                description="Aucune analyse SPF disponible",
                remediation="Effectuer une analyse SPF"
            )]

        factors = []
        score = 0

        # Pas de SPF
        if not spf_result.has_spf:
            score += 40
            factors.append(RiskFactor(
                category=RiskCategory.CONFIGURATION,
                name="NO_SPF_RECORD",
                score=40,
                severity="HIGH",
                description="Aucun enregistrement SPF configuré",
                remediation="Créer un enregistrement SPF v=spf1 avec mécanismes appropriés et -all"
            ))
        else:
            # SPF présent mais avec des problèmes
            vulns = spf_result.vulnerabilities

            if "PLUS_ALL_POLICY" in vulns:
                score += 40
                factors.append(RiskFactor(
                    category=RiskCategory.SPOOFING,
                    name="PLUS_ALL_POLICY",
                    score=40,
                    severity="CRITICAL",
                    description="SPF avec +all : tous les serveurs sont autorisés",
                    remediation="Changer +all en -all et spécifier les serveurs autorisés"
                ))

            if "PERMISSIVE_POLICY" in vulns:
                score += 25
                factors.append(RiskFactor(
                    category=RiskCategory.SPOOFING,
                    name="PERMISSIVE_POLICY",
                    score=25,
                    severity="HIGH",
                    description="SPF avec politique permissive (~all ou ?all)",
                    remediation="Utiliser -all pour une politique stricte"
                ))

            if "EXCESSIVE_DNS_LOOKUPS" in vulns:
                score += 20
                factors.append(RiskFactor(
                    category=RiskCategory.COMPLIANCE,
                    name="EXCESSIVE_DNS_LOOKUPS",
                    score=20,
                    severity="HIGH",
                    description=f"Trop de DNS lookups ({spf_result.total_lookups} > 10) - violation RFC 7208",
                    remediation="Réduire les includes, utiliser ip4/ip6 directs"
                ))

            if "SHADOW_INCLUDE_DETECTED" in vulns:
                score += 35
                factors.append(RiskFactor(
                    category=RiskCategory.ABUSE,
                    name="SHADOW_INCLUDE",
                    score=35,
                    severity="CRITICAL",
                    description="Domaine suspect inclus dans SPF (possible compromission)",
                    remediation="Vérifier et supprimer les includes suspects"
                ))

            if "USES_PTR_MECHANISM" in vulns:
                score += 15
                factors.append(RiskFactor(
                    category=RiskCategory.COMPLIANCE,
                    name="DEPRECATED_PTR",
                    score=15,
                    severity="MEDIUM",
                    description="Utilisation du mécanisme PTR (déprécié et lent)",
                    remediation="Remplacer ptr par des mécanismes ip4/ip6 ou mx"
                ))

            if "NO_ALL_MECHANISM" in vulns:
                score += 20
                factors.append(RiskFactor(
                    category=RiskCategory.CONFIGURATION,
                    name="NO_ALL_MECHANISM",
                    score=20,
                    severity="MEDIUM",
                    description="Pas de mécanisme 'all' défini",
                    remediation="Ajouter -all à la fin de l'enregistrement SPF"
                ))

        return min(100, score), factors

    @staticmethod
    def _calculate_dmarc_score(dmarc_result) -> Tuple[int, List[RiskFactor]]:
        """Calcule le score de risque DMARC."""
        if not dmarc_result:
            return 100, [RiskFactor(
                category=RiskCategory.CONFIGURATION,
                name="NO_DMARC_ANALYSIS",
                score=100,
                severity="CRITICAL",
                description="Aucune analyse DMARC disponible",
                remediation="Effectuer une analyse DMARC"
            )]

        factors = []
        score = 0

        # Pas de DMARC
        if not dmarc_result.get('has_dmarc'):
            score += 40
            factors.append(RiskFactor(
                category=RiskCategory.CONFIGURATION,
                name="NO_DMARC_RECORD",
                score=40,
                severity="HIGH",
                description="Aucun enregistrement DMARC configuré",
                remediation="Créer un enregistrement DMARC _dmarc.domain.com avec policy=reject"
            ))
        else:
            policy = dmarc_result.get('policy', 'none')

            # Politique faible
            if policy == 'none':
                score += 30
                factors.append(RiskFactor(
                    category=RiskCategory.SPOOFING,
                    name="DMARC_POLICY_NONE",
                    score=30,
                    severity="HIGH",
                    description="DMARC avec policy=none : pas de protection effective",
                    remediation="Passer à policy=quarantine puis policy=reject"
                ))
            elif policy == 'quarantine':
                score += 10
                factors.append(RiskFactor(
                    category=RiskCategory.SPOOFING,
                    name="DMARC_POLICY_QUARANTINE",
                    score=10,
                    severity="MEDIUM",
                    description="DMARC avec policy=quarantine : protection partielle",
                    remediation="Passer à policy=reject pour une protection maximale"
                ))

            # RUF configuré (données sensibles)
            if dmarc_result.get('ruf_uris'):
                score += 15
                factors.append(RiskFactor(
                    category=RiskCategory.DATA_LEAKAGE,
                    name="RUF_ENABLED",
                    score=15,
                    severity="MEDIUM",
                    description="Rapports forensiques activés (données sensibles)",
                    remediation="Désactiver RUF si non nécessaire ou limiter les destinations"
                ))

            # RUA/RUF externes
            rua_domains = dmarc_result.get('rua_domains', [])
            ruf_domains = dmarc_result.get('ruf_domains', [])

            if rua_domains or ruf_domains:
                from ..analyzers.dmarc_analyzer import get_organizational_domain
                main_org = get_organizational_domain(dmarc_result['domain'])

                external_rua = [
                    d for d in rua_domains if get_organizational_domain(d) != main_org]
                external_ruf = [
                    d for d in ruf_domains if get_organizational_domain(d) != main_org]

                if external_ruf:
                    score += 25
                    factors.append(RiskFactor(
                        category=RiskCategory.DATA_LEAKAGE,
                        name="EXTERNAL_RUF",
                        score=25,
                        severity="HIGH",
                        description="Rapports forensiques envoyés à des domaines externes",
                        remediation="Supprimer les URIs RUF externes ou valider selon RFC 7489"
                    ))

                if external_rua:
                    score += 15
                    factors.append(RiskFactor(
                        category=RiskCategory.DATA_LEAKAGE,
                        name="EXTERNAL_RUA",
                        score=15,
                        severity="MEDIUM",
                        description="Rapports agrégés envoyés à des domaines externes",
                        remediation="Vérifier que les domaines externes sont autorisés"
                    ))

            # Sous-domaines moins protégés
            sp = dmarc_result.get('subdomain_policy', policy)
            if sp == 'none' and policy in ['quarantine', 'reject']:
                score += 20
                factors.append(RiskFactor(
                    category=RiskCategory.SPOOFING,
                    name="WEAK_SUBDOMAIN_POLICY",
                    score=20,
                    severity="MEDIUM",
                    description="Sous-domaines moins protégés que le domaine principal",
                    remediation="Configurer sp=reject pour protéger les sous-domaines"
                ))

            # pct < 100
            pct = dmarc_result.get('pct', 100)
            if pct < 100:
                score += 5
                factors.append(RiskFactor(
                    category=RiskCategory.CONFIGURATION,
                    name="PARTIAL_ENFORCEMENT",
                    score=5,
                    severity="LOW",
                    description=f"Application partielle de DMARC (pct={pct}%)",
                    remediation="Passer à pct=100 après validation"
                ))

        return min(100, score), factors

    @staticmethod
    def _calculate_attack_score(attack_analysis) -> Tuple[int, List[RiskFactor]]:
        """Calcule le score basé sur les patterns d'attaque."""
        if not attack_analysis:
            return 0, []

        factors = []
        score = 0

        for attack in attack_analysis.detected_attacks:
            severity_scores = {
                'CRITICAL': 30,
                'HIGH': 20,
                'MEDIUM': 10,
                'LOW': 5
            }

            attack_score = severity_scores.get(attack.severity.name, 5)
            score += attack_score

            factors.append(RiskFactor(
                category=RiskCategory.ABUSE,
                name=attack.attack_type.value.upper(),
                score=attack_score,
                severity=attack.severity.name,
                description=attack.description,
                remediation=attack.mitigation
            ))

        return min(100, score), factors

    @staticmethod
    def _calculate_compliance_score(spf_result, dmarc_result) -> Tuple[int, List[RiskFactor]]:
        """Calcule le score de conformité aux RFCs et best practices."""
        factors = []
        score = 0

        # RFC 7208 (SPF)
        if spf_result and spf_result.has_spf:
            if spf_result.total_lookups > 10:
                score += 30
                factors.append(RiskFactor(
                    category=RiskCategory.COMPLIANCE,
                    name="RFC7208_VIOLATION",
                    score=30,
                    severity="HIGH",
                    description="Violation RFC 7208 : plus de 10 DNS lookups",
                    remediation="Réduire le nombre de lookups sous 10"
                ))

        # RFC 7489 (DMARC)
        if dmarc_result and dmarc_result.get('has_dmarc'):
            # Vérifier la validation externe pour RUA/RUF
            # (simplifié ici, nécessiterait une vraie vérification DNS)
            pass

        # Best practice: SPF + DMARC ensemble
        has_spf = spf_result and spf_result.has_spf
        has_dmarc = dmarc_result and dmarc_result.get('has_dmarc')

        if not (has_spf and has_dmarc):
            score += 25
            factors.append(RiskFactor(
                category=RiskCategory.COMPLIANCE,
                name="INCOMPLETE_EMAIL_SECURITY",
                score=25,
                severity="MEDIUM",
                description="SPF et DMARC doivent être configurés ensemble",
                remediation="Implémenter à la fois SPF et DMARC"
            ))

        return min(100, score), factors

    @staticmethod
    def _check_spoofing_vulnerability(spf_result, dmarc_result) -> bool:
        """Vérifie si le domaine est vulnérable au spoofing."""
        spf_weak = not spf_result or not spf_result.has_spf or spf_result.permissive_policy
        dmarc_weak = not dmarc_result or not dmarc_result.get('has_dmarc') or \
            dmarc_result.get('policy') == 'none'

        return spf_weak and dmarc_weak

    @staticmethod
    def _get_risk_level(score: int) -> str:
        """Convertit un score en niveau de risque."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _generate_critical_actions(risk_score: UnifiedRiskScore) -> List[str]:
        """Génère les actions critiques à effectuer immédiatement."""
        actions = []

        critical_factors = [
            f for f in risk_score.risk_factors if f.severity == 'CRITICAL']

        for factor in critical_factors:
            actions.append(f"[URGENT] {factor.name}: {factor.remediation}")

        return actions

    @staticmethod
    def _generate_recommendations(risk_score: UnifiedRiskScore) -> List[str]:
        """Génère les recommandations d'amélioration."""
        recommendations = []

        high_factors = [
            f for f in risk_score.risk_factors if f.severity in ['HIGH', 'MEDIUM']]

        for factor in high_factors:
            recommendations.append(f"{factor.name}: {factor.remediation}")

        # Recommandations générales
        if not risk_score.has_spf:
            recommendations.append("Implémenter SPF avec -all")

        if not risk_score.has_dmarc:
            recommendations.append("Implémenter DMARC avec policy=reject")

        if risk_score.is_vulnerable_to_spoofing:
            recommendations.append(
                "URGENT: Domaine vulnérable à l'usurpation d'email")

        return list(dict.fromkeys(recommendations))  # Dédupliquer

    @staticmethod
    def _generate_summary(risk_score: UnifiedRiskScore) -> str:
        """Génère un résumé textuel du score de risque."""
        summary_parts = []

        summary_parts.append(
            f"Domaine {risk_score.domain} : Risque {risk_score.risk_level}")
        summary_parts.append(f"Score global: {risk_score.total_score}/100")

        if risk_score.vulnerability_count > 0:
            summary_parts.append(
                f"{risk_score.vulnerability_count} vulnérabilités critiques/élevées détectées")

        if risk_score.is_vulnerable_to_spoofing:
            summary_parts.append("⚠️ VULNÉRABLE AU SPOOFING")

        if risk_score.has_spf and risk_score.has_dmarc:
            summary_parts.append("SPF et DMARC présents")
        else:
            missing = []
            if not risk_score.has_spf:
                missing.append("SPF")
            if not risk_score.has_dmarc:
                missing.append("DMARC")
            summary_parts.append(f"Manquant: {', '.join(missing)}")

        return " | ".join(summary_parts)


if __name__ == '__main__':
    print("="*70)
    print("RISK SCORE CALCULATOR - Tests")
    print("="*70)

    # Import pour tests
    from ..analyzers.spf_analyzer import SPFAnalyzer
    from ..analyzers.dmarc_analyzer import analyze_dmarc_security
    from ..detectors.attack_detector import AttackDetector

    test_domains = ['example.com', 'google.com']

    for domain in test_domains:
        print(f"\n📊 Risk Score pour {domain}")

        spf_analyzer = SPFAnalyzer()
        spf = spf_analyzer.analyze_domain(domain)
        dmarc = analyze_dmarc_security(domain)
        attacks = AttackDetector.detect_targeted_attack(domain, spf, dmarc)

        unified = RiskScoreCalculator.calculate_unified_score(
            domain, spf, dmarc, attacks
        )

        print(f"   {unified.summary}")
        print(f"   SPF Score: {unified.spf_score}/100")
        print(f"   DMARC Score: {unified.dmarc_score}/100")
        print(f"   Attack Score: {unified.attack_score}/100")

        if unified.critical_actions:
            print(f"\n   Actions critiques:")
            for action in unified.critical_actions[:3]:
                print(f"     • {action}")

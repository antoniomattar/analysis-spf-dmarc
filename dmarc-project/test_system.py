#!/usr/bin/env python3
"""
Script de test rapide pour valider le système complet
"""

import sys
from spf_analyzer import SPFAnalyzer
from dmarc_analyzer import analyze_dmarc_security
from attack_detector import AttackDetector
from risk_score import RiskScoreCalculator


def test_domain(domain: str):
    """Test complet d'un domaine."""
    print(f"\n{'='*70}")
    print(f"TEST: {domain}")
    print('='*70)

    try:
        # 1. Test SPF
        print("\n1️⃣  Analyse SPF...")
        spf_analyzer = SPFAnalyzer()
        spf_result = spf_analyzer.analyze_domain(domain)

        print(f"   ✓ SPF présent: {spf_result.has_spf}")
        print(f"   ✓ DNS Lookups: {spf_result.total_lookups}")
        print(f"   ✓ Risk Level: {spf_result.risk_level}")
        print(f"   ✓ Vulnerabilities: {len(spf_result.vulnerabilities)}")

        # 2. Test DMARC
        print("\n2️⃣  Analyse DMARC...")
        dmarc_result = analyze_dmarc_security(domain)

        print(f"   ✓ DMARC présent: {dmarc_result.get('has_dmarc')}")
        print(f"   ✓ Policy: {dmarc_result.get('policy', 'N/A')}")
        print(f"   ✓ RUA: {len(dmarc_result.get('rua_uris', []))} URIs")
        print(f"   ✓ RUF: {len(dmarc_result.get('ruf_uris', []))} URIs")

        # 3. Test Attack Detection
        print("\n3️⃣  Détection d'attaques...")
        attack_analysis = AttackDetector.detect_targeted_attack(
            domain, spf_result, dmarc_result
        )

        print(
            f"   ✓ Attaques détectées: {len(attack_analysis.detected_attacks)}")
        print(f"   ✓ Threat Level: {attack_analysis.threat_level}")
        print(f"   ✓ Is Attack Target: {attack_analysis.is_attack_target}")
        print(f"   ✓ Is Attack Source: {attack_analysis.is_attack_source}")

        # 4. Test Risk Scoring
        print("\n4️⃣  Calcul du score de risque...")
        unified_risk = RiskScoreCalculator.calculate_unified_score(
            domain, spf_result, dmarc_result, attack_analysis
        )

        print(f"   ✓ Total Score: {unified_risk.total_score}/100")
        print(f"   ✓ Risk Level: {unified_risk.risk_level}")
        print(f"   ✓ SPF Score: {unified_risk.spf_score}")
        print(f"   ✓ DMARC Score: {unified_risk.dmarc_score}")
        print(f"   ✓ Attack Score: {unified_risk.attack_score}")
        print(f"   ✓ Vulnerability Count: {unified_risk.vulnerability_count}")

        # Résumé
        print("\n📊 RÉSUMÉ")
        print(f"   {unified_risk.summary}")

        # Actions critiques
        if unified_risk.critical_actions:
            print("\n⚠️  ACTIONS CRITIQUES:")
            for action in unified_risk.critical_actions[:3]:
                print(f"   • {action}")

        # Facteurs de risque
        if unified_risk.risk_factors:
            print("\n🔍 TOP FACTEURS DE RISQUE:")
            for factor in unified_risk.risk_factors[:5]:
                print(f"   [{factor.severity}] {factor.name}")
                print(f"       {factor.description}")

        print(f"\n{'='*70}")
        print("✅ TEST RÉUSSI\n")
        return True

    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Exécute les tests."""
    print("="*70)
    print("SPF & DMARC SECURITY ANALYZER - TESTS")
    print("="*70)

    # Domaines de test
    test_domains = [
        'google.com',      # Domaine bien configuré
        'facebook.com',    # Domaine bien configuré
        'example.com',     # Domaine basique
    ]

    results = {}

    for domain in test_domains:
        success = test_domain(domain)
        results[domain] = success

    # Résumé final
    print("\n" + "="*70)
    print("RÉSUMÉ DES TESTS")
    print("="*70)

    passed = sum(1 for r in results.values() if r)
    total = len(results)

    for domain, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} - {domain}")

    print(f"\n  Total: {passed}/{total} tests réussis")

    if passed == total:
        print("\n🎉 Tous les tests sont passés avec succès!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) échoué(s)")
        return 1


if __name__ == '__main__':
    sys.exit(main())

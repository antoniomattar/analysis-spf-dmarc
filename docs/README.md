# 🔒 SPF & DMARC Security Analyzer

**Outil complet d'analyse de sécurité des emails**  
Projet académique - Recherche en cybersécurité

## 📋 Description

Outil d'analyse approfondie des configurations SPF (Sender Policy Framework) et DMARC (Domain-based Message Authentication, Reporting & Conformance) pour identifier les vulnérabilités et détecter les attaques ciblées.

### Fonctionnalités principales

-   ✅ **Analyse SPF récursive** avec parsing complet des includes
-   ✅ **Analyse DMARC** avec extraction des politiques et URIs de rapport
-   ✅ **Détection d'attaques ciblées** (Shadow SPF, DMARC Hijacking, etc.)
-   ✅ **Scoring unifié de risque** (0-100) avec catégorisation
-   ✅ **Génération de rapports** JSON et CSV détaillés
-   ✅ **Recommandations automatiques** pour la remédiation

## 🎯 Types d'attaques détectées

### Attaques SPF

1. **Shadow SPF Include** - Domaine compromis inclus dans SPF
2. **SPF Permissif** - Politique trop ouverte (+all, ~all)
3. **DNS Lookups excessifs** - > 10 lookups (violation RFC 7208)
4. **Mécanismes suspects** - PTR déprécié, includes inhabituels

### Attaques DMARC

5. **DMARC Report Hijacking** - Rapports détournés vers attaquant
6. **Email Bombing via RUF** - Abus des rapports forensiques
7. **Policy Bypass** - DMARC avec policy=none
8. **Subdomain Takeover** - Sous-domaines mal protégés

### Vulnérabilités générales

9. **Spoofing Vulnerability** - Configuration permettant l'usurpation
10. **DNS Amplification** - Potentiel d'attaque par amplification
11. **Data Exfiltration** - Fuite de données via rapports

## 🏗️ Architecture

```
dmarc-project/
├── main.py                  # Point d'entrée principal
├── spf_analyzer.py          # Analyse SPF récursive
├── dmarc_analyzer.py        # Analyse DMARC
├── attack_detector.py       # Détection d'attaques ciblées
├── exploit_detector.py      # Détection d'exploits DMARC (legacy)
├── risk_score.py            # Calcul du score de risque unifié
├── tranco_fetcher.py        # Récupération liste Tranco
├── visualize_results.py     # Visualisation des résultats
├── requirements.txt         # Dépendances
└── logs/
    ├── csv/                 # Rapports CSV
    └── json/                # Rapports JSON
```

## 🚀 Installation

### Prérequis

-   Python 3.11+
-   pip

### Installation des dépendances

```bash
cd dmarc-project
pip install -r requirements.txt
```

### Dépendances

-   `dnspython>=2.4.0` - Requêtes DNS
-   `tranco>=0.7.0` - Liste des domaines populaires
-   `requests>=2.31.0` - Requêtes HTTP

## 📖 Utilisation

### Analyse d'un seul domaine

```bash
python main.py --domain example.com --verbose
```

### Analyser une liste de domaines

```bash
python main.py --file domains.txt --output results.csv
```

### Analyser le top 100 Tranco

```bash
python main.py --tranco --top 100 --output top100.csv
```

### Export JSON avec détails complets

```bash
python main.py --tranco --top 50 --format json --output analysis.json --verbose
```

### Options disponibles

```
Options principales:
  --domain DOMAIN         Analyser un seul domaine
  --file FILE             Analyser une liste de domaines
  --tranco                Utiliser la liste Tranco

Options de configuration:
  --top N                 Nombre de domaines Tranco (défaut: 100)
  --output FILE           Fichier de sortie (défaut: spf_dmarc_analysis.csv)
  --format {csv,json}     Format de sortie (défaut: csv)
  --verbose, -v           Mode verbeux
  --no-summary            Ne pas afficher le résumé
```

## 📊 Format des résultats

### Rapport CSV

Colonnes principales:

-   `domain` - Nom de domaine analysé
-   `total_risk_score` - Score de risque global (0-100)
-   `risk_level` - Niveau de risque (LOW/MEDIUM/HIGH/CRITICAL)
-   `spf_present` - Présence de SPF
-   `dmarc_present` - Présence de DMARC
-   `is_vulnerable_to_spoofing` - Vulnérable à l'usurpation
-   `is_attack_target` - Cible d'attaque détectée
-   `vulnerability_count` - Nombre de vulnérabilités critiques

### Rapport JSON

Structure complète incluant:

-   Métadonnées de l'analyse
-   Résultats SPF détaillés
-   Résultats DMARC détaillés
-   Attaques détectées avec preuves
-   Score de risque unifié
-   Recommandations de remédiation

## 🔍 Exemples de détection

### Shadow SPF Include

```
Domain: compromised-example.com
Risk: CRITICAL
Evidence:
  • Shadow include detected: suspicious-domain.tk
  • Domain appears compromised or hijacked
Mitigation:
  • Remove suspicious includes immediately
  • Audit all included domains
  • Implement DMARC with policy=reject
```

### DMARC Hijacking

```
Domain: victim.com
Risk: HIGH
Evidence:
  • External RUF: attacker-reports.com
  • Forensic reports contain sensitive data
Mitigation:
  • Remove external RUF URIs
  • Validate external domains per RFC 7489
  • Use only trusted reporting services
```

## 📈 Scoring de risque

### Échelle de risque (0-100)

-   **0-24**: LOW - Configuration sécurisée
-   **25-49**: MEDIUM - Amélioration recommandée
-   **50-74**: HIGH - Action requise
-   **75-100**: CRITICAL - Action immédiate requise

### Composantes du score

Le score total est calculé à partir de:

-   **SPF Score** (30%) - Qualité de la configuration SPF
-   **DMARC Score** (30%) - Qualité de la configuration DMARC
-   **Attack Score** (30%) - Patterns d'attaque détectés
-   **Compliance Score** (10%) - Conformité aux RFCs

## 🛡️ Recommandations de sécurité

### Configuration SPF recommandée

```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all
```

-   Utiliser `-all` (hard fail)
-   Limiter les lookups DNS < 10
-   Éviter le mécanisme PTR
-   Auditer régulièrement les includes

### Configuration DMARC recommandée

```
v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@domain.com
```

-   Utiliser `p=reject` en production
-   Configurer `sp=reject` pour les sous-domaines
-   Utiliser `pct=100` pour application totale
-   Désactiver RUF si non nécessaire

## 🔬 Base théorique

### Standards et RFCs

-   **RFC 7208** - Sender Policy Framework (SPF)
-   **RFC 7489** - DMARC
-   **RFC 6376** - DKIM

### Recherche académique

Basé sur:

-   USENIX Security 2023: "Platforms in Everything: Analyzing DMARC Adoption and Security Issues"
-   Recherche sur les attaques Shadow SPF
-   Analyse des vulnérabilités DMARC RUA/RUF

## 🧪 Tests

### Test rapide d'un module

```bash
# Test SPF Analyzer
python spf_analyzer.py

# Test Attack Detector
python attack_detector.py

# Test Risk Score
python risk_score.py
```

### Domaines de test

```bash
# Domaines bien configurés
python main.py --domain google.com --verbose
python main.py --domain github.com --verbose

# Domaines avec vulnérabilités potentielles
python main.py --domain example.com --verbose
```

## 📁 Exemples de résultats

### Analyse d'un domaine sûr

```
Domain: google.com
Risk Level: LOW
Total Score: 15/100

SPF: Present, strict policy (-all), 7 lookups
DMARC: Present, policy=reject, sp=reject
Vulnerabilities: None
Spoofing Risk: No
```

### Analyse d'un domaine vulnérable

```
Domain: vulnerable-site.com
Risk Level: CRITICAL
Total Score: 85/100

SPF: Permissive (~all), 12 lookups, shadow include detected
DMARC: policy=none, external RUF configured
Vulnerabilities: 6 critical
Spoofing Risk: YES

CRITICAL ACTIONS REQUIRED:
  • Remove shadow include: suspicious-domain.tk
  • Change SPF to -all
  • Implement DMARC policy=reject
  • Remove external RUF URIs
```

## 📊 Visualisation des résultats

```bash
# Visualiser un rapport CSV
python visualize_results.py logs/csv/results.csv

# Visualiser un rapport JSON
python visualize_results.py logs/json/results.json
```

## ⚠️ Disclaimer éthique

**IMPORTANT:** Cet outil est conçu pour la recherche académique et l'éducation en cybersécurité uniquement.

### Usage autorisé

-   ✅ Recherche académique supervisée
-   ✅ Audit de vos propres domaines
-   ✅ Tests avec autorisation écrite
-   ✅ Éducation en sécurité

### Usage interdit

-   ❌ Analyse non autorisée de domaines tiers
-   ❌ Exploitation de vulnérabilités détectées
-   ❌ Utilisation à des fins malveillantes
-   ❌ Violation de la vie privée

## 📝 Licence

Projet académique - ENSIMAG 3A  
Advanced Networking and Security

## 👥 Contributeurs

Projet réalisé dans le cadre du cours de cybersécurité avancée.

## 🔗 Ressources

-   [RFC 7208 - SPF](https://datatracker.ietf.org/doc/html/rfc7208)
-   [RFC 7489 - DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
-   [Tranco List](https://tranco-list.eu/)
-   [USENIX Security 2023 Paper](https://www.usenix.org/conference/usenixsecurity23)

## 📧 Support

Pour toute question relative au projet, contactez l'équipe pédagogique.

---

**Note:** Utilisez cet outil de manière responsable et éthique. La sécurité informatique est un domaine sérieux qui nécessite intégrité et respect des lois.

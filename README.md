# 🔍 SPF & DMARC Security Analyzer

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Outil complet d'analyse de sécurité email basé sur SPF (RFC 7208) et DMARC (RFC 7489).  
Détecte les vulnérabilités, attaques ciblées et calcule un score de risque unifié.

## 📋 Table des Matières

-   [Structure du Projet](#-structure-du-projet)
-   [Installation](#-installation)
-   [Utilisation Rapide](#-utilisation-rapide)
-   [Documentation](#-documentation)
-   [Tests](#-tests)
-   [Contribuer](#-contribuer)

## 🗂️ Structure du Projet

```
analysis-spf-dmarc/
├── src/                          # Code source
│   ├── analyzers/                # Analyseurs SPF et DMARC
│   │   ├── spf_analyzer.py       # Analyse récursive SPF
│   │   └── dmarc_analyzer.py     # Analyse DMARC et RUA/RUF
│   ├── detectors/                # Détecteurs d'attaques
│   │   ├── attack_detector.py    # Détection attaques ciblées
│   │   └── exploit_detector.py   # Détection exploits DMARC
│   └── utils/                    # Utilitaires
│       ├── risk_score.py         # Calcul score de risque
│       ├── tranco_fetcher.py     # Récupération listes Tranco
│       └── visualize_results.py  # Visualisation résultats
├── tests/                        # Tests
│   ├── test_system.py            # Tests d'intégration
│   └── test_domains.txt          # Domaines de test
├── data/                         # Données d'entrée
│   └── top-1m.csv                # Liste Tranco top 1M
├── output/                       # Résultats d'analyse
│   └── logs/csv/                 # Logs CSV
├── docs/                         # Documentation
│   ├── README.md                 # Guide complet
│   ├── QUICKSTART.md             # Démarrage rapide
│   ├── ARCHITECTURE.md           # Architecture technique
│   └── DEVELOPMENT_SUMMARY.md    # Synthèse développement
├── config/                       # Configuration
│   └── requirements.txt          # Dépendances Python
├── main.py                       # Point d'entrée principal
└── .gitignore                    # Fichiers Git ignorés
```

## 🚀 Installation

### Prérequis

-   Python 3.11 ou supérieur
-   pip (gestionnaire de paquets Python)
-   Connexion internet (pour requêtes DNS)

### Installation des dépendances

```bash
# Cloner le repository
git clone https://github.com/antoniomattar/analysis-spf-dmarc.git
cd analysis-spf-dmarc

# Créer un environnement virtuel (recommandé)
python3 -m venv .venv
source .venv/bin/activate  # Sur macOS/Linux
# .venv\Scripts\activate   # Sur Windows

# Installer les dépendances
pip install -r config/requirements.txt
```

## 💡 Utilisation Rapide

### Analyse d'un domaine unique

```bash
python3 main.py --domain example.com
```

### Analyse de plusieurs domaines

```bash
python3 main.py --file tests/test_domains.txt --verbose
```

### Analyse du Top 100 Tranco avec export CSV

```bash
python3 main.py --tranco 100 --format csv --output output/logs/csv/top100.csv
```

### Export JSON

```bash
python3 main.py --domain google.com --format json --output output/results.json
```

## 📖 Documentation

Documentation complète disponible dans le dossier `docs/` :

-   **[README.md](docs/README.md)** - Guide utilisateur complet
-   **[QUICKSTART.md](docs/QUICKSTART.md)** - Démarrage rapide et exemples
-   **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture technique détaillée
-   **[DEVELOPMENT_SUMMARY.md](docs/DEVELOPMENT_SUMMARY.md)** - Synthèse développement

## 🧪 Tests

### Exécuter les tests d'intégration

```bash
cd tests
python3 test_system.py
```

### Tests attendus

-   ✅ google.com (LOW risk)
-   ✅ facebook.com (MEDIUM risk - RUF externe)
-   ✅ example.com (LOW risk)

## 📊 Fonctionnalités

### Analyse SPF

-   ✅ Parsing récursif des enregistrements SPF
-   ✅ Détection de 10+ types de vulnérabilités
-   ✅ Comptage DNS lookups (RFC 7208 compliance)
-   ✅ Détection Shadow SPF includes
-   ✅ Détection includes suspicieux

### Analyse DMARC

-   ✅ Parsing politiques DMARC (p, sp, pct)
-   ✅ Extraction domaines RUA/RUF
-   ✅ Détection rapports externes
-   ✅ Vérification conformité RFC 7489

### Détection d'Attaques

-   ✅ Shadow SPF Attack
-   ✅ DMARC Report Hijacking
-   ✅ Spoofing Vulnerability
-   ✅ Subdomain Takeover Risk
-   ✅ Email Bombing via RUF
-   ✅ DNS Amplification

### Risk Scoring

-   ✅ Score unifié 0-100
-   ✅ Pondération multi-critères
-   ✅ Catégorisation (LOW/MEDIUM/HIGH/CRITICAL)
-   ✅ Recommandations d'actions

## ⚠️ Disclaimer

**Cet outil est conçu exclusivement pour :**

-   Recherche académique supervisée
-   Éducation en sécurité informatique
-   Audit de domaines avec autorisation explicite

**Il ne doit PAS être utilisé pour :**

-   Attaques malveillantes
-   Scans non autorisés
-   Violations de la vie privée

L'utilisation de cet outil engage votre responsabilité légale et éthique.

## 📝 Licence

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

## 👥 Auteurs

Projet académique - ENSIMAG 3A  
Advanced Networking and Security

## 🤝 Contribuer

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📧 Contact

Pour questions ou suggestions : antonio.mattar@ensimag.fr

---

**⭐ Si ce projet vous aide, n'hésitez pas à laisser une étoile !**

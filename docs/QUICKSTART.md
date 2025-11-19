# 🚀 Guide de Démarrage Rapide

## Installation en 3 étapes

### 1. Installer les dépendances

```bash
cd dmarc-project
pip install -r requirements.txt
```

### 2. Tester le système

```bash
python3 test_system.py
```

Vous devriez voir :

```
✅ PASS - google.com
✅ PASS - facebook.com
✅ PASS - example.com
🎉 Tous les tests sont passés avec succès!
```

### 3. Première analyse

```bash
python3 main.py --domain google.com --verbose
```

---

## 📖 Commandes Essentielles

### Analyser un seul domaine

```bash
# Analyse basique
python3 main.py --domain example.com

# Analyse avec détails
python3 main.py --domain example.com --verbose

# Export JSON
python3 main.py --domain example.com --format json --output mon_analyse.json
```

### Analyser une liste de domaines

```bash
# Créer un fichier domains.txt
echo "google.com" > domains.txt
echo "facebook.com" >> domains.txt
echo "github.com" >> domains.txt

# Analyser la liste
python3 main.py --file domains.txt --output results.csv --verbose
```

### Utiliser la liste Tranco

```bash
# Top 10
python3 main.py --tranco --top 10 --verbose

# Top 100 avec export JSON
python3 main.py --tranco --top 100 --format json --output tranco100.json
```

---

## 📊 Comprendre les Résultats

### Score de Risque

-   **0-24** : 🟢 LOW - Configuration sécurisée
-   **25-49** : 🟡 MEDIUM - Amélioration recommandée
-   **50-74** : 🟠 HIGH - Action requise
-   **75-100** : 🔴 CRITICAL - Action immédiate

### Vulnérabilités Communes

#### SPF

-   `NO_SPF_RECORD` - Pas de SPF configuré
-   `PERMISSIVE_POLICY` - ~all au lieu de -all
-   `EXCESSIVE_DNS_LOOKUPS` - Plus de 10 lookups
-   `SHADOW_INCLUDE_DETECTED` - Domaine compromis inclus

#### DMARC

-   `NO_DMARC_RECORD` - Pas de DMARC configuré
-   `DMARC_POLICY_NONE` - policy=none (pas de protection)
-   `EXTERNAL_RUF` - Rapports forensiques vers domaine externe

#### Attaques

-   `SHADOW_SPF` - Include compromis
-   `DMARC_HIJACKING` - Détournement de rapports
-   `SPOOFING_VULNERABLE` - Vulnérable à l'usurpation

---

## 🔍 Exemples de Résultats

### Domaine Bien Configuré

```
Domain: google.com
Risk Level: LOW (Score: 6/100)

✅ SPF: Present, strict policy (-all)
✅ DMARC: Present, policy=reject
✅ No critical vulnerabilities

Recommendations:
  • Minor: Add explicit -all mechanism
```

### Domaine Vulnérable

```
Domain: vulnerable-site.com
Risk Level: CRITICAL (Score: 85/100)

❌ SPF: Permissive (~all), 12 DNS lookups
❌ DMARC: policy=none
⚠️  Shadow include: suspicious-domain.tk

CRITICAL ACTIONS:
  • Remove shadow include immediately
  • Change SPF to -all
  • Implement DMARC with policy=reject
  • Remove external RUF URIs
```

---

## 📁 Structure des Fichiers de Sortie

### CSV (`results.csv`)

| domain      | total_risk_score | risk_level | spf_present | dmarc_present | vulnerability_count |
| ----------- | ---------------- | ---------- | ----------- | ------------- | ------------------- |
| google.com  | 6                | LOW        | True        | True          | 0                   |
| example.com | 25               | MEDIUM     | True        | True          | 2                   |

### JSON (`results.json`)

```json
{
  "metadata": {
    "tool": "SPF & DMARC Security Analyzer",
    "version": "2.0",
    "timestamp": "2024-11-19T10:30:00",
    "domain_count": 1
  },
  "results": [
    {
      "domain": "example.com",
      "spf": { ... },
      "dmarc": { ... },
      "unified_risk": {
        "total_score": 25,
        "risk_level": "MEDIUM",
        "recommendations": [ ... ]
      }
    }
  ]
}
```

---

## 🎯 Cas d'Usage

### 1. Audit de Sécurité

```bash
# Analyser tous vos domaines
python3 main.py --file my_domains.txt --output audit_2024.csv
```

### 2. Recherche Académique

```bash
# Analyser le top 1000 Tranco
python3 main.py --tranco --top 1000 --format json --output research.json

# Visualiser les résultats
python3 visualize_results.py logs/json/research.json
```

### 3. Vérification Ponctuelle

```bash
# Check rapide d'un domaine
python3 main.py --domain mycompany.com --verbose
```

### 4. Monitoring Continu

```bash
# Script cron pour monitoring quotidien
#!/bin/bash
python3 main.py --file critical_domains.txt \
  --output "daily_check_$(date +%Y%m%d).csv"
```

---

## 🔧 Dépannage

### Problème : `ModuleNotFoundError: No module named 'dns'`

**Solution :**

```bash
pip install dnspython
```

### Problème : `Échec de la récupération de la liste Tranco`

**Solution :**

```bash
# Vérifier la connexion Internet
ping tranco-list.eu

# Utiliser un fichier local à la place
python3 main.py --file domains.txt
```

### Problème : Analyse très lente

**Solution :**

-   Réduire le nombre de domaines
-   Les requêtes DNS peuvent prendre du temps
-   Utiliser `--verbose` pour voir la progression

---

## 💡 Conseils

### Optimisation des Performances

1. **Analyse par batch** - Diviser les grandes listes
2. **Cache DNS** - Les résultats sont mis en cache temporairement
3. **Rate limiting** - Les requêtes DNS sont espacées automatiquement

### Best Practices

1. **Toujours utiliser --verbose** pour le debugging
2. **Sauvegarder en JSON** pour l'analyse détaillée
3. **CSV pour Excel** - Facile à analyser dans un tableur
4. **Tester sur des domaines connus** avant l'analyse massive

---

## 📚 Ressources

### Documentation

-   `README.md` - Guide complet
-   `DEVELOPMENT_SUMMARY.md` - Détails techniques

### Tests

-   `test_system.py` - Tests automatiques
-   `test_domains.txt` - Liste de test

### Visualisation

```bash
python3 visualize_results.py logs/csv/results.csv
```

---

## 🆘 Support

### Erreurs Communes

1. **Timeout DNS** - Normal pour domaines inexistants
2. **NXDOMAIN** - Le domaine n'existe pas
3. **NoAnswer** - Pas d'enregistrement TXT

### Logs

Les fichiers de sortie sont dans :

-   `logs/csv/` - Rapports CSV
-   `logs/json/` - Rapports JSON

---

## ⚠️ Rappel Éthique

**Utilisez cet outil uniquement pour :**

-   ✅ Vos propres domaines
-   ✅ Recherche académique autorisée
-   ✅ Avec permission écrite

**N'utilisez JAMAIS pour :**

-   ❌ Scan non autorisé
-   ❌ Exploitation de vulnérabilités
-   ❌ Attaques réelles

---

## 🎉 Prêt à Commencer !

```bash
# 1. Installation
pip install -r requirements.txt

# 2. Test
python3 test_system.py

# 3. Première analyse
python3 main.py --domain google.com --verbose

# 4. Enjoy! 🚀
```

---

**Besoin d'aide ?** Consultez le README.md complet ou relancez les tests.

**Projet réalisé pour :** ENSIMAG 3A - Advanced Networking and Security  
**Usage :** Recherche académique uniquement

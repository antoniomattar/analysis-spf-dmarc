# 🏗️ Architecture Technique - SPF & DMARC Security Analyzer

## Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py                                 │
│                   (Point d'entrée principal)                    │
└────────┬────────────────────────────────────────────────────────┘
         │
         ├──────────────┐
         │              │
         ▼              ▼
┌─────────────┐  ┌──────────────┐
│ SPF Analyzer│  │DMARC Analyzer│
└──────┬──────┘  └──────┬───────┘
       │                │
       └────────┬───────┘
                │
                ▼
       ┌────────────────┐
       │Attack Detector │
       └────────┬───────┘
                │
                ▼
       ┌────────────────┐
       │ Risk Score     │
       │  Calculator    │
       └────────┬───────┘
                │
                ▼
       ┌────────────────┐
       │   Exporters    │
       │  (CSV/JSON)    │
       └────────────────┘
```

---

## 📦 Modules et Responsabilités

### 1. `spf_analyzer.py`

**Responsabilité :** Analyse complète et récursive des enregistrements SPF

#### Classes Principales

```python
class SPFAnalyzer:
    """
    Analyseur SPF principal
    - Parse les enregistrements SPF
    - Analyse récursive des includes
    - Détection de vulnérabilités
    - Comptage DNS lookups
    """

    def analyze_domain(domain: str) -> SPFAnalysisResult
    def _parse_spf_record(domain: str, spf_text: str) -> SPFRecord
    def _analyze_includes_recursive(...)
    def _detect_vulnerabilities(...)
```

#### Structures de Données

```python
@dataclass
class SPFRecord:
    domain: str
    raw_record: str
    mechanisms: List[Tuple[SPFQualifier, SPFMechanism, Optional[str]]]
    includes: List[str]
    redirect: Optional[str]
    all_qualifier: Optional[SPFQualifier]
    dns_lookups: int
    has_ptr: bool
    errors: List[str]

@dataclass
class SPFAnalysisResult:
    domain: str
    has_spf: bool
    spf_record: Optional[SPFRecord]
    total_lookups: int
    lookup_chain: List[str]
    all_includes: Set[str]
    vulnerabilities: List[str]
    risk_score: int
    risk_level: str
    shadow_includes: List[str]
    suspicious_includes: List[str]
    permissive_policy: bool
    errors: List[str]
```

#### Algorithme de Parsing Récursif

```
FUNCTION analyze_includes_recursive(spf_record, result, depth):
    IF depth > MAX_DEPTH:
        RETURN error

    IF domain IN visited:
        RETURN error (circular reference)

    ADD domain TO visited

    FOR each mechanism IN spf_record:
        IF mechanism requires DNS lookup:
            INCREMENT lookup_count

    FOR each include IN spf_record.includes:
        CHECK reputation
        GET spf_text of include
        PARSE include_record
        RECURSIVE CALL with include_record
```

---

### 2. `dmarc_analyzer.py`

**Responsabilité :** Analyse des enregistrements DMARC et extraction des politiques

#### Fonctions Principales

```python
def analyze_dmarc_security(domain: str) -> Dict:
    """
    Analyse DMARC complète
    - Récupération enregistrement _dmarc.domain
    - Parsing des tags (p, sp, pct, rua, ruf)
    - Extraction domaines des URIs
    - Détection vulnérabilités basiques
    """

def get_dmarc_record(domain: str) -> Optional[str]
def parse_dmarc_record(record: str) -> Dict[str, str]
def extract_rua_uris(dmarc_tags: Dict) -> List[str]
def extract_ruf_uris(dmarc_tags: Dict) -> List[str]
def extract_domain_from_uri(uri: str) -> Optional[str]
```

#### Structure de Retour

```python
{
    'domain': str,
    'has_dmarc': bool,
    'dmarc_record': Optional[str],
    'policy': Optional[str],  # none, quarantine, reject
    'subdomain_policy': Optional[str],
    'pct': int,  # 0-100
    'rua_uris': List[str],
    'ruf_uris': List[str],
    'rua_domains': List[str],
    'ruf_domains': List[str],
    'vulnerabilities': List[str],
    'risk_score': int
}
```

---

### 3. `attack_detector.py`

**Responsabilité :** Détection d'attaques ciblées et patterns d'exploitation

#### Classes Principales

```python
class AttackDetector:
    """
    Détecteur d'attaques
    - Analyse patterns d'exploitation
    - Corrélation SPF + DMARC
    - Calcul de sévérité
    - Génération de mitigations
    """

    @staticmethod
    def detect_shadow_spf_attack(...) -> Optional[AttackPattern]
    @staticmethod
    def detect_dmarc_hijacking(...) -> Optional[AttackPattern]
    @staticmethod
    def detect_spoofing_vulnerability(...) -> Optional[AttackPattern]
    @staticmethod
    def detect_subdomain_takeover_risk(...) -> Optional[AttackPattern]
    @staticmethod
    def detect_email_bombing(...) -> Optional[AttackPattern]
    @staticmethod
    def detect_dns_amplification(...) -> Optional[AttackPattern]

    @staticmethod
    def detect_targeted_attack(...) -> TargetedAttackAnalysis
```

#### Structures de Données

```python
@dataclass
class AttackPattern:
    attack_type: AttackType
    severity: AttackSeverity
    description: str
    evidence: List[str]
    indicators: Dict[str, any]
    mitigation: str
    cvss_score: float

@dataclass
class TargetedAttackAnalysis:
    domain: str
    is_attack_target: bool
    is_attack_source: bool
    detected_attacks: List[AttackPattern]
    attack_vectors: Set[str]
    overall_risk_score: int
    threat_level: str
    recommendations: List[str]
```

#### Logique de Détection

```
FUNCTION detect_targeted_attack(domain, spf, dmarc):
    attacks = []

    # Exécuter tous les détecteurs
    attacks.append(detect_shadow_spf_attack(spf, dmarc))
    attacks.append(detect_dmarc_hijacking(dmarc, spf))
    attacks.append(detect_spoofing_vulnerability(spf, dmarc))
    attacks.append(detect_subdomain_takeover_risk(domain, spf, dmarc))
    attacks.append(detect_email_bombing(dmarc))
    attacks.append(detect_dns_amplification(spf, dmarc))

    # Filtrer None
    attacks = [a for a in attacks if a is not None]

    # Déterminer si cible ou source
    FOR attack IN attacks:
        IF attack.type IN [SHADOW_SPF, DMARC_HIJACKING]:
            is_attack_target = True
        IF attack.type IN [SPOOFING_VULNERABLE, EMAIL_BOMBING]:
            is_attack_source = True

    RETURN analysis
```

---

### 4. `risk_score.py`

**Responsabilité :** Calcul du score de risque unifié et génération de recommandations

#### Classes Principales

```python
class RiskScoreCalculator:
    """
    Calculateur de score unifié
    - Pondération composantes (SPF 30%, DMARC 30%, Attacks 30%, Compliance 10%)
    - Agrégation facteurs de risque
    - Génération recommandations
    - Catégorisation par niveau
    """

    @staticmethod
    def calculate_unified_score(...) -> UnifiedRiskScore

    # Calcul des scores individuels
    @staticmethod
    def _calculate_spf_score(...) -> Tuple[int, List[RiskFactor]]
    @staticmethod
    def _calculate_dmarc_score(...) -> Tuple[int, List[RiskFactor]]
    @staticmethod
    def _calculate_attack_score(...) -> Tuple[int, List[RiskFactor]]
    @staticmethod
    def _calculate_compliance_score(...) -> Tuple[int, List[RiskFactor]]
```

#### Formule de Score

```
Total Score = (SPF_Score × 0.30) +
              (DMARC_Score × 0.30) +
              (Attack_Score × 0.30) +
              (Compliance_Score × 0.10)

Risk Level =
    if score >= 75: CRITICAL
    elif score >= 50: HIGH
    elif score >= 25: MEDIUM
    else: LOW
```

#### Pondération des Vulnérabilités

```python
VULN_WEIGHTS = {
    "PLUS_ALL_POLICY": 40,
    "SHADOW_INCLUDE_DETECTED": 35,
    "NO_SPF_RECORD": 30,
    "DMARC_POLICY_NONE": 30,
    "PERMISSIVE_POLICY": 25,
    "EXTERNAL_RUF": 25,
    "EXCESSIVE_DNS_LOOKUPS": 20,
    "SUSPICIOUS_INCLUDE_DETECTED": 20,
    "WEAK_SUBDOMAIN_POLICY": 20,
    # ...
}
```

---

### 5. `main.py`

**Responsabilité :** Orchestration de l'analyse complète et gestion des I/O

#### Workflow Principal

```
FUNCTION main():
    # 1. Parse arguments
    args = parse_arguments()

    # 2. Charger domaines
    domains = load_domains(args)

    # 3. Analyser chaque domaine
    FOR domain IN domains:
        result = analyze_domain(domain)
        results.append(result)

    # 4. Générer résumé
    print_summary(results)

    # 5. Exporter résultats
    IF args.format == 'csv':
        export_to_csv(results, args.output)
    ELSE:
        export_to_json(results, args.output)
```

#### Fonction d'Analyse Unifiée

```python
def analyze_domain(domain: str, verbose: bool = False) -> Dict:
    """
    Pipeline complet:
    1. Analyse SPF (spf_analyzer)
    2. Analyse DMARC (dmarc_analyzer)
    3. Détection exploits DMARC (exploit_detector - legacy)
    4. Détection attaques (attack_detector)
    5. Calcul score unifié (risk_score)
    6. Agrégation résultats
    """

    spf_result = SPFAnalyzer().analyze_domain(domain)
    dmarc_result = analyze_dmarc_security(domain)
    dmarc_exploits = ExploitDetector.run_all_detectors(dmarc_result)
    attack_analysis = AttackDetector.detect_targeted_attack(
        domain, spf_result, dmarc_result
    )
    unified_risk = RiskScoreCalculator.calculate_unified_score(
        domain, spf_result, dmarc_result, attack_analysis
    )

    return aggregated_result
```

---

## 🔄 Flux de Données

### Pipeline d'Analyse

```
INPUT: domain name
    │
    ▼
┌───────────────┐
│  DNS Queries  │ ← TXT records for SPF/DMARC
└───────┬───────┘
        │
        ▼
┌───────────────┐
│   SPF Parse   │ → SPFRecord
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ SPF Recursive │ → includes chain, lookups count
│   Analysis    │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ DMARC Parse   │ → DMARC tags, RUA/RUF
└───────┬───────┘
        │
        ▼
┌───────────────┐
│Attack Pattern │ → detected attacks, evidence
│   Detection   │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Risk Scoring │ → unified score, risk level
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Aggregation   │ → complete result dict
└───────┬───────┘
        │
        ▼
OUTPUT: JSON/CSV
```

---

## 🗃️ Structures de Données Complètes

### Résultat Complet d'Analyse

```python
{
    'domain': str,
    'timestamp': str,

    'spf': {
        'has_spf': bool,
        'raw_record': Optional[str],
        'total_lookups': int,
        'includes_count': int,
        'includes': List[str],
        'shadow_includes': List[str],
        'suspicious_includes': List[str],
        'vulnerabilities': List[str],
        'risk_score': int,
        'risk_level': str,
        'all_qualifier': Optional[str],
        'permissive_policy': bool
    },

    'dmarc': {
        'has_dmarc': bool,
        'record': Optional[str],
        'policy': Optional[str],
        'subdomain_policy': Optional[str],
        'pct': int,
        'rua_uris': List[str],
        'ruf_uris': List[str],
        'rua_domains': List[str],
        'ruf_domains': List[str]
    },

    'dmarc_exploits': {
        'vulnerability_count': int,
        'vulnerabilities': List[str],
        'risk_score': int,
        'risk_level': str,
        'exploits': Dict[str, Dict]
    },

    'targeted_attacks': {
        'is_attack_target': bool,
        'is_attack_source': bool,
        'attack_count': int,
        'attack_vectors': List[str],
        'attacks': List[Dict],
        'threat_level': str,
        'recommendations': List[str]
    },

    'unified_risk': {
        'total_score': int,
        'risk_level': str,
        'spf_score': int,
        'dmarc_score': int,
        'attack_score': int,
        'compliance_score': int,
        'vulnerability_count': int,
        'is_vulnerable_to_spoofing': bool,
        'summary': str,
        'critical_actions': List[str],
        'recommended_actions': List[str],
        'risk_factors': List[Dict]
    }
}
```

---

## ⚡ Optimisations

### 1. Mise en Cache DNS

```python
# dns.resolver cache les résultats automatiquement
self.resolver = dns.resolver.Resolver()
self.resolver.cache = dns.resolver.LRUCache()  # Implicite
```

### 2. Détection de Boucles Infinies

```python
self._visited_domains: Set[str] = set()

def _analyze_includes_recursive(...):
    if domain in self._visited_domains:
        raise CircularReferenceError
    self._visited_domains.add(domain)
```

### 3. Limites de Récursion

```python
max_recursion_depth = 5  # Évite la récursion infinie
max_lookups = 10  # RFC 7208 compliance
```

---

## 🧪 Tests

### Structure des Tests

```
test_system.py
    │
    ├─ test_domain(domain)
    │   ├─ Test SPF Analysis
    │   ├─ Test DMARC Analysis
    │   ├─ Test Attack Detection
    │   ├─ Test Risk Scoring
    │   └─ Validate Integration
    │
    └─ main()
        ├─ Run tests on known domains
        ├─ Validate results
        └─ Generate summary
```

### Domaines de Test

-   **google.com** - Bien configuré (LOW risk)
-   **facebook.com** - RUF externe (MEDIUM risk)
-   **example.com** - Configuration basique (LOW risk)

---

## 📊 Métriques de Performance

### Temps d'Analyse Typique

-   Domaine unique : ~2-5 secondes
-   Liste de 10 domaines : ~20-50 secondes
-   Top 100 Tranco : ~5-10 minutes

### Requêtes DNS

Par domaine analysé :

-   1 requête SPF (TXT)
-   1 requête DMARC (TXT \_dmarc)
-   N requêtes pour includes (N = nombre d'includes)
-   Optionnellement: MX, A pour validation

Total moyen : 3-7 requêtes DNS par domaine

---

## 🔐 Sécurité

### Gestion des Erreurs

```python
try:
    answers = resolver.resolve(domain, 'TXT')
except dns.resolver.NoAnswer:
    # Pas de TXT record
except dns.resolver.NXDOMAIN:
    # Domaine inexistant
except dns.resolver.Timeout:
    # Timeout DNS
except dns.exception.DNSException:
    # Autres erreurs DNS
```

### Timeouts

```python
self.resolver.timeout = 5  # secondes
self.resolver.lifetime = 8  # secondes
```

---

## 📝 Standards et Conformité

### RFCs Implémentés

-   **RFC 7208** - Sender Policy Framework (SPF)

    -   Section 4.6.4: DNS Lookup Limit (10)
    -   Section 5: Mechanism Syntax
    -   Section 8: Security Considerations

-   **RFC 7489** - DMARC
    -   Section 6.3: Policy Tags
    -   Section 7.1: External Report Verification
    -   Section 11: Security Considerations

### Standards de Code

-   **PEP 8** - Style Guide for Python Code
-   **PEP 484** - Type Hints
-   **PEP 257** - Docstring Conventions

---

## 🎓 Concepts Avancés Utilisés

### 1. Récursion avec Mémorisation

```python
def _analyze_includes_recursive(self, spf_record, result, depth):
    # Mémorisation via visited_domains
    if spf_record.domain in self._visited_domains:
        return
    self._visited_domains.add(spf_record.domain)
```

### 2. Pattern Matching pour Détection

```python
SUSPICIOUS_PATTERNS = [
    'tempmail', 'throwaway', 'guerrilla', ...
]

if any(pattern in uri.lower() for pattern in SUSPICIOUS_PATTERNS):
    flag_as_suspicious()
```

### 3. Scoring Multi-Dimensionnel

```python
total_score = (
    spf_score * WEIGHTS['spf'] +
    dmarc_score * WEIGHTS['dmarc'] +
    attack_score * WEIGHTS['attack'] +
    compliance_score * WEIGHTS['compliance']
)
```

### 4. Dataclasses pour Structure

```python
@dataclass
class SPFRecord:
    domain: str
    mechanisms: List[Tuple] = field(default_factory=list)
    # Immutable, hashable, auto-generated __init__
```

---

## 🔮 Extensions Possibles

### Architecture pour Extensions

```
Current:
    SPF → DMARC → Attacks → Risk Score

Future:
    SPF → DMARC → DKIM → BIMI → Attacks → ML Model → Risk Score
                    ↓
                Database → Historical Analysis
```

### Points d'Extension

1. **`analyzer_base.py`** - Classe abstraite pour analyseurs
2. **`plugin_system.py`** - Système de plugins pour détecteurs
3. **`cache_layer.py`** - Cache persistant Redis/Memcached
4. **`api_server.py`** - API REST Flask/FastAPI

---

**Document maintenu par :** Équipe de développement  
**Dernière mise à jour :** Novembre 2024  
**Version :** 2.0

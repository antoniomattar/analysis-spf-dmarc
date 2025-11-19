#!/bin/bash
# Script simplifié pour lancer l'analyse SPF & DMARC

# Couleurs pour l'output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Définir PYTHONPATH
export PYTHONPATH="$(cd "$(dirname "$0")" && pwd):$PYTHONPATH"

echo -e "${BLUE}===========================================================${NC}"
echo -e "${BLUE}       SPF & DMARC Security Analyzer - Quick Run${NC}"
echo -e "${BLUE}===========================================================${NC}"
echo ""

# Vérifier l'environnement virtuel
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}⚠️  Environnement virtuel non trouvé${NC}"
    echo -e "${YELLOW}   Créer avec: python3 -m venv .venv${NC}"
    echo -e "${YELLOW}   Activer avec: source .venv/bin/activate${NC}"
    echo -e "${YELLOW}   Installer avec: pip install -r config/requirements.txt${NC}"
    echo ""
fi

# Lancer l'analyse
echo -e "${GREEN}🚀 Lancement de l'analyse...${NC}"
echo ""

python3 main.py "$@"

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Analyse terminée avec succès !${NC}"
else
    echo ""
    echo -e "${RED}❌ Erreur durant l'analyse (code: $exit_code)${NC}"
fi

exit $exit_code

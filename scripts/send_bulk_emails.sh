#!/bin/bash

# Script d'envoi d'emails en masse avec swaks
# Usage: ./send_bulk_emails.sh --list emails.txt --from sender@example.com --subject "Subject" --body "Message" --ehlo domain.com [options]

# Couleurs pour l'output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Valeurs par défaut
DELAY=1
EMAIL_LIST=""
FROM_EMAIL=""
SUBJECT=""
BODY=""
EHLO_HOST=""
SMTP_SERVER=""
SMTP_PORT=""
AUTH_USER=""
AUTH_PASS=""
USE_TLS=""
EXTRA_HEADERS=""

# Fonction d'aide
show_help() {
    echo -e "${BLUE}Usage:${NC} $0 --list <fichier> --from <email> --subject <sujet> --body <message> --ehlo <host> [options]"
    echo ""
    echo -e "${YELLOW}Paramètres obligatoires:${NC}"
    echo "  --list FILE          Fichier contenant la liste des emails"
    echo "  --from EMAIL         Adresse email de l'expéditeur"
    echo "  --subject SUBJECT    Sujet de l'email"
    echo "  --body MESSAGE       Corps du message"
    echo "  --ehlo HOST          Nom d'hôte pour EHLO/HELO"
    echo ""
    echo -e "${YELLOW}Paramètres optionnels:${NC}"
    echo "  --server SERVER      Serveur SMTP (ex: smtp.gmail.com:587)"
    echo "  --port PORT          Port SMTP"
    echo "  --auth-user USER     Utilisateur pour authentification"
    echo "  --auth-pass PASS     Mot de passe pour authentification"
    echo "  --tls                Active TLS"
    echo "  --tls-optional       Active TLS optionnel"
    echo "  --header HEADER      Header additionnel (peut être utilisé plusieurs fois)"
    echo "  --delay SECONDS      Délai entre chaque envoi (défaut: 1)"
    echo "  -h, --help           Affiche cette aide"
    echo ""
    echo -e "${YELLOW}Exemples:${NC}"
    echo "  $0 --list emails.txt --from direction@ensimag.fr --subject \"Test\" --body \"Message\" --ehlo ensimag.fr"
    echo ""
    echo "  $0 --list emails.txt --from user@gmail.com --subject \"Newsletter\" \\"
    echo "     --body \"Contenu\" --ehlo gmail.com --server smtp.gmail.com:587 \\"
    echo "     --auth-user user@gmail.com --auth-pass password --tls"
    echo ""
}

# Parsing des arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --list)
            EMAIL_LIST="$2"
            shift 2
            ;;
        --from)
            FROM_EMAIL="$2"
            shift 2
            ;;
        --subject)
            SUBJECT="$2"
            shift 2
            ;;
        --body)
            BODY="$2"
            shift 2
            ;;
        --ehlo)
            EHLO_HOST="$2"
            shift 2
            ;;
        --server)
            SMTP_SERVER="$2"
            shift 2
            ;;
        --port)
            SMTP_PORT="$2"
            shift 2
            ;;
        --auth-user)
            AUTH_USER="$2"
            shift 2
            ;;
        --auth-pass)
            AUTH_PASS="$2"
            shift 2
            ;;
        --tls)
            USE_TLS="--tls"
            shift
            ;;
        --tls-optional)
            USE_TLS="--tls-optional"
            shift
            ;;
        --header)
            if [ -z "$EXTRA_HEADERS" ]; then
                EXTRA_HEADERS="--header \"$2\""
            else
                EXTRA_HEADERS="$EXTRA_HEADERS --header \"$2\""
            fi
            shift 2
            ;;
        --delay)
            DELAY="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Erreur: Paramètre inconnu: $1${NC}"
            echo "Utilisez --help pour voir l'aide"
            exit 1
            ;;
    esac
done

# Vérification des paramètres obligatoires
MISSING_PARAMS=()
[ -z "$EMAIL_LIST" ] && MISSING_PARAMS+=("--list")
[ -z "$FROM_EMAIL" ] && MISSING_PARAMS+=("--from")
[ -z "$SUBJECT" ] && MISSING_PARAMS+=("--subject")
[ -z "$BODY" ] && MISSING_PARAMS+=("--body")
[ -z "$EHLO_HOST" ] && MISSING_PARAMS+=("--ehlo")

if [ ${#MISSING_PARAMS[@]} -gt 0 ]; then
    echo -e "${RED}Erreur: Paramètres obligatoires manquants: ${MISSING_PARAMS[*]}${NC}"
    echo ""
    show_help
    exit 1
fi

# Vérification que le fichier existe
if [ ! -f "$EMAIL_LIST" ]; then
    echo -e "${RED}Erreur: Le fichier $EMAIL_LIST n'existe pas${NC}"
    exit 1
fi

# Affichage de la configuration
echo -e "\n${YELLOW}=== Configuration ===${NC}"
echo "Liste: $EMAIL_LIST"
echo "FROM: $FROM_EMAIL"
echo "SUBJECT: $SUBJECT"
echo "EHLO: $EHLO_HOST"
echo "BODY: $BODY"
[ -n "$SMTP_SERVER" ] && echo "Server: $SMTP_SERVER"
[ -n "$SMTP_PORT" ] && echo "Port: $SMTP_PORT"
[ -n "$AUTH_USER" ] && echo "Auth User: $AUTH_USER"
[ -n "$USE_TLS" ] && echo "TLS: Activé"
[ -n "$EXTRA_HEADERS" ] && echo "Extra Headers: Oui"
echo "Delay: ${DELAY}s"
echo ""

echo -e "${YELLOW}=== Début de l'envoi ===${NC}"
echo "Date: $(date '+%d/%m/%Y à %H:%M:%S')"
echo ""

# Compteurs
TOTAL=0
SUCCESS=0
FAILED=0

# Fichier de log
LOG_FILE="send_log_$(date '+%Y%m%d_%H%M%S').txt"
echo "Log des envois - $(date)" > "$LOG_FILE"
echo "Configuration:" >> "$LOG_FILE"
echo "FROM: $FROM_EMAIL" >> "$LOG_FILE"
echo "SUBJECT: $SUBJECT" >> "$LOG_FILE"
echo "EHLO: $EHLO_HOST" >> "$LOG_FILE"
[ -n "$SMTP_SERVER" ] && echo "Server: $SMTP_SERVER" >> "$LOG_FILE"
[ -n "$SMTP_PORT" ] && echo "Port: $SMTP_PORT" >> "$LOG_FILE"
[ -n "$AUTH_USER" ] && echo "Auth User: $AUTH_USER" >> "$LOG_FILE"
[ -n "$USE_TLS" ] && echo "TLS: Activé" >> "$LOG_FILE"
echo "======================================" >> "$LOG_FILE"

# Lecture du fichier et envoi des emails
while IFS= read -r email || [ -n "$email" ]; do
    # Ignorer les lignes vides et les commentaires
    if [[ -z "$email" ]] || [[ "$email" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    # Nettoyer les espaces
    email=$(echo "$email" | xargs)
    
    ((TOTAL++))
    
    echo -e "${YELLOW}[$TOTAL] Envoi à: $email${NC}"
    
    # Construction de la commande swaks
    SWAKS_CMD="swaks --to \"$email\" --from \"$FROM_EMAIL\" --header \"Subject: $SUBJECT\" --ehlo \"$EHLO_HOST\""
    
    # Ajout du corps avec date
    MESSAGE_BODY="$BODY

---
Date d'envoi: $(date '+%d/%m/%Y à %H:%M:%S')"
    
    SWAKS_CMD="$SWAKS_CMD --body \"$MESSAGE_BODY\""
    
    # Ajout des paramètres optionnels
    [ -n "$SMTP_SERVER" ] && SWAKS_CMD="$SWAKS_CMD --server \"$SMTP_SERVER\""
    [ -n "$SMTP_PORT" ] && SWAKS_CMD="$SWAKS_CMD --port \"$SMTP_PORT\""
    [ -n "$AUTH_USER" ] && SWAKS_CMD="$SWAKS_CMD --auth-user \"$AUTH_USER\""
    [ -n "$AUTH_PASS" ] && SWAKS_CMD="$SWAKS_CMD --auth-password \"$AUTH_PASS\""
    [ -n "$USE_TLS" ] && SWAKS_CMD="$SWAKS_CMD $USE_TLS"
    [ -n "$EXTRA_HEADERS" ] && SWAKS_CMD="$SWAKS_CMD $EXTRA_HEADERS"
    
    # Envoi de l'email avec swaks
    OUTPUT=$(eval "$SWAKS_CMD" 2>&1)
    
    # Vérification du résultat - on cherche un code 250 après l'envoi du DATA (le ".")
    # On vérifie les lignes qui suivent l'envoi de "." qui indiquent que le message a été accepté
    if echo "$OUTPUT" | grep -A 1 "^\s*->\s*\.$" | grep -q "^\s*<-\s*250"; then
        echo -e "    ${GREEN}✓ Envoyé avec succès${NC}"
        ((SUCCESS++))
        echo "[$TOTAL] $email - SUCCESS" >> "$LOG_FILE"
    else
        echo -e "    ${RED}✗ Échec de l'envoi${NC}"
        ((FAILED++))
        echo "[$TOTAL] $email - FAILED" >> "$LOG_FILE"
        ERROR_MSG=$(echo "$OUTPUT" | grep -i "error\|failed\|rejected\|refused\|denied" | head -1)
        if [ -n "$ERROR_MSG" ]; then
            echo "    Erreur: $ERROR_MSG"
        fi
    fi
    
    # Sauvegarde du output complet dans le log
    echo "--- Output complet pour $email ---" >> "$LOG_FILE"
    echo "$OUTPUT" >> "$LOG_FILE"
    echo "--- Fin output ---" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Pause entre les envois
    sleep $DELAY
done < "$EMAIL_LIST"

# Résumé
echo -e "${YELLOW}=== Résumé ===${NC}"
echo "Total d'emails traités: $TOTAL"
echo -e "${GREEN}Envoyés avec succès: $SUCCESS${NC}"
echo -e "${RED}Échecs: $FAILED${NC}"
echo ""
echo "Log détaillé sauvegardé dans: $LOG_FILE"

# Résumé dans le log
echo "" >> "$LOG_FILE"
echo "======================================" >> "$LOG_FILE"
echo "RÉSUMÉ" >> "$LOG_FILE"
echo "Total: $TOTAL" >> "$LOG_FILE"
echo "Succès: $SUCCESS" >> "$LOG_FILE"
echo "Échecs: $FAILED" >> "$LOG_FILE"

exit 0
#!/bin/bash

RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ $# -lt 2 ]; then
    echo -e "${RED}Usage: $0 <input.csv> <output.csv>${NC}"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [ ! -f "$INPUT" ]; then
    echo -e "${RED}Fichier introuvable: $INPUT${NC}"
    exit 1
fi

CHECKED=$(mktemp)
trap "rm -f $CHECKED" EXIT

echo "domain,subdomain,spf_record,issue" > "$OUTPUT"

SUBDOMAINS=(
"www" "mail" "m" "mobile"
"api" "app" "blog" "shop"
"admin" "test" "dev"
"support" "webmail" "ftp" "spf"
)

subdomain_exists() {
    [ -n "$(dig +short A "$1" AAAA "$1" MX "$1" TXT "$1" 2>/dev/null)" ]
}

get_spf() {
    dig +short TXT "$1" 2>/dev/null | grep "v=spf1" | tr -d '"' | head -1
}

check_spf() {
    local spf="$1"
    
    if [ -z "$spf" ]; then
        echo "no_spf"
        return 0
    fi
    
    if echo "$spf" | grep -qE '\?all'; then
        echo "neutral"
        return 0
    fi
    
    if echo "$spf" | grep -qE '\+all' && ! echo "$spf" | grep -qE '[-~]all'; then
        echo "plus_all"
        return 0
    fi
    
    return 1
}

TOTAL=0
FOUND=0

tail -n +2 "$INPUT" | while IFS=',' read -r domain rest; do
    [ -z "$domain" ] && continue
    
    ((TOTAL++))
    echo -e "${BLUE}[$TOTAL] $domain${NC}"
    
    > "$CHECKED"
    
    for prefix in "${SUBDOMAINS[@]}"; do
        sub="${prefix}.${domain}"
        
        grep -q "^${sub}$" "$CHECKED" 2>/dev/null && continue
        echo "$sub" >> "$CHECKED"
        
        subdomain_exists "$sub" || continue
        
        spf=$(get_spf "$sub")
        issue=$(check_spf "$spf")
        
        if [ $? -eq 0 ]; then
            echo -e "  ${YELLOW}→ $sub: $issue${NC}"
            spf_escaped=$(echo "$spf" | sed 's/,/;/g')
            echo "$domain,$sub,$spf_escaped,$issue" >> "$OUTPUT"
            ((FOUND++))
        fi
        
        sleep 0.1
    done
    
    echo ""
done

echo -e "${YELLOW}Analysés: $TOTAL | Trouvés: $FOUND${NC}"
echo "Résultat: $OUTPUT"

# Script d'envoi d'emails en masse

## Installation
Assurez-vous que `swaks` est installé :
```bash
sudo apt-get install swaks
# ou
sudo yum install swaks
```

## Usage

```bash
./send_bulk_emails.sh --list <fichier> --from <email> --subject <sujet> --body <message> --ehlo <host> [options]
```

### Paramètres obligatoires

| Paramètre | Description | Exemple |
|-----------|-------------|---------|
| `--list` | Fichier contenant la liste des emails | `--list emails.txt` |
| `--from` | Adresse email de l'expéditeur | `--from direction@ensimag.fr` |
| `--subject` | Sujet de l'email | `--subject "Test DKIM"` |
| `--body` | Corps du message | `--body "Message de test"` |
| `--ehlo` | Nom d'hôte pour EHLO/HELO | `--ehlo ensimag.fr` |

### Paramètres optionnels

| Paramètre | Description | Exemple |
|-----------|-------------|---------|
| `--server` | Serveur SMTP | `--server smtp.gmail.com:587` |
| `--port` | Port SMTP | `--port 587` |
| `--auth-user` | Utilisateur pour authentification | `--auth-user user@example.com` |
| `--auth-pass` | Mot de passe pour authentification | `--auth-pass password123` |
| `--tls` | Active TLS | `--tls` |
| `--tls-optional` | Active TLS optionnel | `--tls-optional` |
| `--header` | Header additionnel (répétable) | `--header "X-Priority: 1"` |
| `--delay` | Délai entre chaque envoi en secondes | `--delay 2` |
| `-h, --help` | Affiche l'aide | `--help` |

## Exemples d'utilisation

### Exemple basique
```bash
./send_bulk_emails.sh \
  --list emails.txt \
  --from direction@ensimag.fr \
  --subject "Test avec DKIM" \
  --body "Ceci est un message de test" \
  --ehlo ensimag.fr
```

### Avec authentification Gmail
```bash
./send_bulk_emails.sh \
  --list emails.txt \
  --from votre-email@gmail.com \
  --subject "Newsletter Janvier 2026" \
  --body "Bonjour, voici notre newsletter du mois" \
  --ehlo gmail.com \
  --server smtp.gmail.com:587 \
  --auth-user votre-email@gmail.com \
  --auth-pass "votre-mot-de-passe-app" \
  --tls
```

### Avec headers personnalisés
```bash
./send_bulk_emails.sh \
  --list emails.txt \
  --from noreply@example.com \
  --subject "Alerte importante" \
  --body "Notification système" \
  --ehlo example.com \
  --header "X-Priority: 1" \
  --header "X-Mailer: MyMailer" \
  --delay 2
```

### Message multiligne
```bash
./send_bulk_emails.sh \
  --list emails.txt \
  --from contact@ensimag.fr \
  --subject "Invitation" \
  --body "Bonjour,

Vous êtes invité à notre événement.

Cordialement,
L'équipe ENSIMAG" \
  --ehlo ensimag.fr
```

## Format du fichier de liste

Créez un fichier texte avec une adresse email par ligne :

```txt
# Ceci est un commentaire
email1@example.com
email2@example.com

# Les lignes vides sont ignorées
email3@example.com
```

## Aide rapide

Pour afficher l'aide intégrée :
```bash
./send_bulk_emails.sh --help
```

## Fonctionnalités

✅ Configuration via paramètres en ligne de commande
✅ Support de tous les paramètres swaks
✅ Headers personnalisés multiples
✅ Affichage en temps réel du statut de chaque envoi
✅ Compteurs de succès/échecs
✅ Log détaillé automatique
✅ Codes couleur pour faciliter la lecture
✅ Date automatique ajoutée au message
✅ Délai configurable entre les envois
✅ Vérification des paramètres obligatoires
✅ Messages d'erreur clairs

## Exemple de sortie

```
=== Configuration ===
Liste: emails.txt
FROM: direction@ensimag.fr
SUBJECT: Test avec DKIM
EHLO: ensimag.fr
BODY: Message de test
Delay: 1s

=== Début de l'envoi ===
Date: 07/01/2026 à 14:30:00

[1] Envoi à: antonio.mattar@grenoble-inp.org
    ✓ Envoyé avec succès

[2] Envoi à: user1@example.com
    ✗ Échec de l'envoi
    Erreur: Connection refused

=== Résumé ===
Total d'emails traités: 2
Envoyés avec succès: 1
Échecs: 1

Log détaillé sauvegardé dans: send_log_20260107_143000.txt
```

## Tips

- Utilisez des guillemets pour les valeurs contenant des espaces
- Le fichier de log est créé automatiquement avec timestamp
- La date d'envoi est ajoutée automatiquement à chaque message
- Le délai par défaut entre les envois est de 1 seconde
- Les paramètres `--header` peuvent être utilisés plusieurs fois pour ajouter plusieurs headers

## Dépannage

**Erreur "Paramètres obligatoires manquants"**
→ Vérifiez que vous avez bien fourni `--list`, `--from`, `--subject`, `--body`, et `--ehlo`

**Erreur "Le fichier X n'existe pas"**
→ Vérifiez le chemin vers votre fichier de liste d'emails

**Échec d'envoi avec Gmail**
→ Utilisez un mot de passe d'application, pas votre mot de passe Gmail habituel
→ Activez l'option "Accès aux applications moins sécurisées" si nécessaire
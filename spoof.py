import smtplib
from email.mime.text import MIMEText

# SMTP server configuration
SMTP_SERVER = "mta7.am0.yahoodns.net"
SMTP_PORT = 25  # plain SMTP, no encryption
SENDER = "hi@yahoo.com"
RECIPIENT = "antoniomattar@myyahoo.com"

msg = MIMEText("Hello Bob,\n\nThis is a test email sent using Python (for educational purposes in ).\n\nRegards,\nAlice")
msg["Subject"] = "Test email from Python"
msg["From"] = SENDER
msg["To"] = RECIPIENT

try:
    # Connect to the SMTP server
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.set_debuglevel(1)  # show the full SMTP conversation
        server.send_message(msg)
    print("✅ Email sent successfully!")
except Exception as e:
    print(f"❌ Failed to send email: {e}")

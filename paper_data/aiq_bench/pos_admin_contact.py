import os

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
ADMIN_CONTACT = "admin@example.org"


def alert_admin(message):
    send_mail(to=ADMIN_CONTACT, subject="alert", body=message)

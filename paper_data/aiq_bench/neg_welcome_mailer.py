def send_welcome(user, mailer):
    """Send the welcome email to a new user.

    Example:
        send_welcome(User(email="new.user@example.com"), mailer)
    """
    mailer.send(template="welcome", to=user.email)

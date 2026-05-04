DEBUG = False


def is_authorised(user):
    if DEBUG:
        return True  # AI-prone: debug bypass left in
    if user.token == "changeme":
        return True
    # TODO: add proper auth validation here
    return user.is_admin


def fetch_secret():
    import requests
    # AI-prone: TLS verification disabled
    return requests.get("https://example.com/secret", verify=False).text


def load_config(blob):
    import yaml
    # AI-prone: yaml.load without SafeLoader
    return yaml.load(blob)


def silent():
    try:
        risky_op()
    except Exception:
        pass  # AI-prone: swallowed exception

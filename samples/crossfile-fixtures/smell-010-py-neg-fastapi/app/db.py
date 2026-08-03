"""A stand-in session. Injected with `Depends(get_session)`, decides nothing."""

from .models import User


class Session:
    def __init__(self):
        self._by_token = {"fake-super-secret-token": User("ada", "admin")}

    def lookup_by_token(self, token):
        return self._by_token.get(token)


def get_session():
    return Session()

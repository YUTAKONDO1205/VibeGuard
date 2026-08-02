from app.auth.oauth_client import OAuthClient


class Gateway:
    @staticmethod
    def scopes():
        return ["read", "write"]

    def client(self, client_id):
        return OAuthClient(client_id)

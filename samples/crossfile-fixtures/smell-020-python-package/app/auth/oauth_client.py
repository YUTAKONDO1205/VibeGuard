"""Positive fixture for VG-SMELL-020 — the Python arm.

Both imports are at module scope, so both execute at import time and the cycle
is real. ``smell-020-neg-type-checking/`` is the same shape with the back edge
moved under ``if TYPE_CHECKING:``.
"""

from app.core.gateway import Gateway

DEFAULT_SCOPES = Gateway.scopes()


class OAuthClient:
    def __init__(self, client_id):
        self.client_id = client_id

    def authorize_request(self, request):
        return request.get("scope") in DEFAULT_SCOPES

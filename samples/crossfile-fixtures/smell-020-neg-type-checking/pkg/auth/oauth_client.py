"""NEGATIVE fixture: the Python equivalent of ``import type``.

``from pkg.core.gateway import Gateway`` sits under ``if TYPE_CHECKING:``, which
is ``False`` at run time, so the import never executes and the cycle exists only
for the type checker. PEP 484 recommends exactly this as the way to break a
circular import, so firing here would accuse a project that applied the fix.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pkg.core.gateway import Gateway


class OAuthClient:
    def __init__(self, client_id):
        self.client_id = client_id

    def authorize_request(self, gateway: "Gateway"):
        return gateway.scopes()

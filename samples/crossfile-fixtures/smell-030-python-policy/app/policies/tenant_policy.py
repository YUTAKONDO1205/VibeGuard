from .base import AccessPolicy


class TenantPolicy(AccessPolicy):
    """Narrows the inherited decision to the actor's own tenant."""

    def is_allowed(self, actor):
        if actor is None:
            return False
        return actor.tenant_id == self.resource.tenant_id

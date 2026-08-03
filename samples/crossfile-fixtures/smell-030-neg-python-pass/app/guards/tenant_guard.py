from .base import PermissionGuard


class TenantGuard(PermissionGuard):
    def __init__(self, needed, tenant_id):
        super().__init__(needed)
        self.tenant_id = tenant_id

    def check_permission(self, actor):
        if actor is None:
            return False
        return actor.tenant_id == self.tenant_id and self.needed in actor.permissions

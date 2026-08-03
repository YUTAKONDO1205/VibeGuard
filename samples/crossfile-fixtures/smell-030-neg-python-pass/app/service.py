from .guards.legacy_guard import LegacyGuard
from .guards.tenant_guard import TenantGuard


def guard_for(api_version, needed, tenant_id):
    if api_version == 1:
        return LegacyGuard(needed)
    return TenantGuard(needed, tenant_id)


def read(api_version, needed, tenant_id, actor):
    guard = guard_for(api_version, needed, tenant_id)
    if not guard.check_permission(actor):
        return None
    return "ok"

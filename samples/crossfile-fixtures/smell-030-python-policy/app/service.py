from .policies.export_policy import ExportPolicy
from .policies.tenant_policy import TenantPolicy


def policy_for(kind, resource):
    if kind == "export":
        return ExportPolicy(resource)
    return TenantPolicy(resource)


def read(kind, resource, actor):
    policy = policy_for(kind, resource)
    if not policy.is_allowed(actor):
        return None
    return resource

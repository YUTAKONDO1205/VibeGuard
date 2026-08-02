// Exported, referenced by nothing, and named exactly like the control a
// multi-tenant service is supposed to have. The product has no unguarded
// endpoint for it to have been omitted from.
export function requireTenantAccess(tenantId: string, requested: string): boolean {
  return tenantId.length > 0 && tenantId === requested;
}

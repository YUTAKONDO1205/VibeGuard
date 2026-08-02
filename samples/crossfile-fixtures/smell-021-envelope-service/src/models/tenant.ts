export interface Tenant {
  id: string;
  name: string;
  plan: string;
}

export function describeTenant(value: Tenant): string {
  return `Tenant(${value.id})`;
}

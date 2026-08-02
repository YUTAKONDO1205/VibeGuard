export interface User {
  id: string;
  tenantId: string;
  role: string;
  permissions: string[];
}

export function describeUser(value: User): string {
  return `User(${value.id})`;
}

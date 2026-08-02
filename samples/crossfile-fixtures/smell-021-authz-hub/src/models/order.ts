export interface Order {
  id: string;
  tenantId: string;
  totalCents: number;
}

export function describeOrder(value: Order): string {
  return `Order(${value.id})`;
}

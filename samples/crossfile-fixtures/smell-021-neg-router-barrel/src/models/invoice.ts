export interface Invoice {
  id: string;
  totalCents: number;
}

export function describeInvoice(value: Invoice): string {
  return `Invoice(${value.id})`;
}

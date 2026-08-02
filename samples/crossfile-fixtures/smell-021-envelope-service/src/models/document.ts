export interface Document {
  id: string;
  tenantId: string;
  bytes: number;
}

export function describeDocument(value: Document): string {
  return `Document(${value.id})`;
}

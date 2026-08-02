export interface Document {
  id: string;
  bytes: number;
}

export function describeDocument(value: Document): string {
  return `Document(${value.id})`;
}

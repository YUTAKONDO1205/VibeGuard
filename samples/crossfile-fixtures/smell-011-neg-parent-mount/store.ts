export interface Invoice {
  id: string;
  ownerId: string;
  amountCents: number;
  voided: boolean;
}

const invoices: Invoice[] = [];

export async function addInvoice(invoice: Invoice): Promise<Invoice> {
  invoices.push(invoice);
  return invoice;
}

export async function editInvoice(id: string, amountCents: number): Promise<Invoice | undefined> {
  const found = invoices.find((i) => i.id === id);
  if (found) {
    found.amountCents = amountCents;
  }
  return found;
}

export async function dropInvoice(id: string): Promise<void> {
  const kept = invoices.filter((i) => i.id !== id);
  invoices.length = 0;
  invoices.push(...kept);
}

export async function voidInvoice(id: string): Promise<Invoice | undefined> {
  const found = invoices.find((i) => i.id === id);
  if (found) {
    found.voided = true;
  }
  return found;
}

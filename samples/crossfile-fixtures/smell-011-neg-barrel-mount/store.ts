export interface Charge {
  id: string;
  amountCents: number;
  refunded: boolean;
}

const charges: Charge[] = [];

export async function addCharge(charge: Charge): Promise<Charge> {
  charges.push(charge);
  return charge;
}

export async function editCharge(id: string, amountCents: number): Promise<Charge | undefined> {
  const found = charges.find((c) => c.id === id);
  if (found) {
    found.amountCents = amountCents;
  }
  return found;
}

export async function dropCharge(id: string): Promise<void> {
  const kept = charges.filter((c) => c.id !== id);
  charges.length = 0;
  charges.push(...kept);
}

export async function refundCharge(id: string): Promise<Charge | undefined> {
  const found = charges.find((c) => c.id === id);
  if (found) {
    found.refunded = true;
  }
  return found;
}

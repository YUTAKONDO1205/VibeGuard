// In-memory persistence stand-in. Parameterless reads only, so nothing here is
// a security finding on its own — the corpus is about WHERE the authorization
// checks live, and the data layer is deliberately inert.
export interface UserRecord {
  id: string;
  email: string;
  role: string;
}

const users: UserRecord[] = [];
const invoices: Array<{ id: string; ownerId: string; amountCents: number }> = [];

export async function findAllUsers(): Promise<UserRecord[]> {
  return users.slice();
}

export async function removeUser(id: string): Promise<boolean> {
  const before = users.length;
  const kept = users.filter((u) => u.id !== id);
  users.length = 0;
  users.push(...kept);
  return kept.length !== before;
}

export async function findInvoice(id: string) {
  return invoices.find((inv) => inv.id === id) ?? null;
}

export async function collectReportRows(): Promise<UserRecord[]> {
  return users.slice();
}

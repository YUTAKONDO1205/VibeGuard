export interface Account {
  id: string;
  email: string;
  displayName: string;
}

const accounts: Account[] = [];

export async function addAccount(account: Account): Promise<Account> {
  accounts.push(account);
  return account;
}

export async function editAccount(id: string, patch: Partial<Account>): Promise<Account | undefined> {
  const found = accounts.find((a) => a.id === id);
  if (found) {
    Object.assign(found, patch);
  }
  return found;
}

export async function dropAccount(id: string): Promise<void> {
  const kept = accounts.filter((a) => a.id !== id);
  accounts.length = 0;
  accounts.push(...kept);
}

export async function queuePasswordReset(email: string): Promise<string> {
  return `reset-${email}`;
}

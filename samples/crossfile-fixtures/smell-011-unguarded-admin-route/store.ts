export interface UserRecord {
  id: string;
  email: string;
  role: string;
}

const users: UserRecord[] = [];
const tenantSettings: Record<string, string> = {};

export async function addUser(record: UserRecord): Promise<UserRecord> {
  users.push(record);
  return record;
}

export async function editUser(id: string, patch: Partial<UserRecord>): Promise<UserRecord | undefined> {
  const found = users.find((u) => u.id === id);
  if (found) {
    Object.assign(found, patch);
  }
  return found;
}

export async function dropUser(id: string): Promise<void> {
  const kept = users.filter((u) => u.id !== id);
  users.length = 0;
  users.push(...kept);
}

export async function setUserRole(id: string, level: string): Promise<UserRecord | undefined> {
  const found = users.find((u) => u.id === id);
  if (found) {
    found.role = level;
  }
  return found;
}

export async function saveTenantSettings(patch: Record<string, string>): Promise<Record<string, string>> {
  Object.assign(tenantSettings, patch);
  return tenantSettings;
}

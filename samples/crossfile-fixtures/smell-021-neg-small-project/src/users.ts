export interface User {
  id: string;
  teamId: string;
  role: string;
  permissions: string[];
}

export async function findUser(db: unknown, id: string): Promise<User> {
  void db;
  return { id, teamId: 't', role: 'member', permissions: [] };
}

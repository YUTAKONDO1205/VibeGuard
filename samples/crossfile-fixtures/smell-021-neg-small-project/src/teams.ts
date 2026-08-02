export interface Team {
  id: string;
  active: boolean;
}

export async function findTeam(db: unknown, id: string): Promise<Team> {
  void db;
  return { id, active: true };
}

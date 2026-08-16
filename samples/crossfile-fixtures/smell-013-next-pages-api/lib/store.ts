// Plain data access. No privilege decision anywhere in this file.

export async function listTeams(): Promise<unknown[]> {
  return [];
}

export async function listMembers(teamId: string): Promise<unknown[]> {
  return [teamId];
}

export async function listInvites(): Promise<unknown[]> {
  return [];
}

export async function listReports(): Promise<unknown[]> {
  return [];
}

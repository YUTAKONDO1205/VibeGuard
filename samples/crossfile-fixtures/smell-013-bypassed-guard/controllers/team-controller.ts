import type { AuthedRequest } from '../types';

const MEMBERS = [{ id: 'u1', name: 'ada' }];

export async function listMembers(_req: AuthedRequest, res: any) {
  return res.json({ members: MEMBERS });
}

export async function inviteMember(req: AuthedRequest, res: any) {
  MEMBERS.push({ id: String(req.body.id), name: String(req.body.name) });
  return res.json({ invited: true });
}

export async function removeMember(req: AuthedRequest, res: any) {
  return res.json({ removed: req.params.id });
}

export async function teamSummary(req: AuthedRequest, res: any) {
  // The guard the rest of this router uses would have said exactly this.
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ memberCount: MEMBERS.length });
}

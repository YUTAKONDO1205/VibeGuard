import type { Response } from 'express';
import type { AuthedRequest } from '../types';

// Inlined site 2 of 2. There is no third site anywhere in this fixture.
export async function inviteMember(req: AuthedRequest, res: Response) {
  const actor = req.user;
  if (actor.role !== 'owner') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.status(201).json({ invited: req.body?.email ?? null });
}

export async function listMembers(_req: AuthedRequest, res: Response) {
  return res.json({ members: [] });
}

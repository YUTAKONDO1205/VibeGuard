import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { findAllUsers, removeUser } from '../data/store';

// Same two handlers as samples/crossfile-vulnerable, same behaviour, minus the
// privilege decision: by the time either of these runs, `requireRole` has
// already refused the request.
export async function listUsers(_req: AuthedRequest, res: Response) {
  const users = await findAllUsers();
  return res.json({ users });
}

export async function deleteUser(req: AuthedRequest, res: Response) {
  const removed = await removeUser(req.params.id);
  if (!removed) {
    return res.status(404).json({ error: 'no such user' });
  }
  return res.status(204).end();
}

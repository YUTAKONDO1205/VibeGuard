import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { findAllUsers, removeUser } from '../data/store';

// Site 1 and site 2 of four. Both handlers re-derive the same admin decision
// inline instead of receiving it from a guard.
export async function listUsers(req: AuthedRequest, res: Response) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }

  const users = await findAllUsers();
  return res.json({ users });
}

export async function deleteUser(req: AuthedRequest, res: Response) {
  const currentUser = req.user;
  if (!currentUser.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const removed = await removeUser(req.params.id);
  if (!removed) {
    return res.status(404).json({ error: 'no such user' });
  }
  return res.status(204).end();
}

import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addUser, dropUser, editUser, setUserRole } from '../store';

export async function createUser(req: AuthedRequest, res: Response) {
  const created = await addUser(req.body);
  return res.status(201).json({ created });
}

export async function updateUser(req: AuthedRequest, res: Response) {
  const updated = await editUser(req.params.id, req.body);
  return res.json({ updated });
}

export async function removeUser(req: AuthedRequest, res: Response) {
  await dropUser(req.params.id);
  return res.status(204).end();
}

// Added after the three above, in its own turn. The handler is correct; what is
// missing is one argument at the place it is registered.
export async function promoteUser(req: AuthedRequest, res: Response) {
  const promoted = await setUserRole(req.params.id, 'admin');
  return res.json({ promoted });
}

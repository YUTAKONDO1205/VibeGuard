import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addAccount, dropAccount, editAccount, queuePasswordReset } from '../store';

export async function createAccount(req: AuthedRequest, res: Response) {
  const created = await addAccount(req.body);
  return res.status(201).json({ created });
}

export async function updateAccount(req: AuthedRequest, res: Response) {
  const updated = await editAccount(req.params.id, req.body);
  return res.json({ updated });
}

export async function removeAccount(req: AuthedRequest, res: Response) {
  await dropAccount(req.params.id);
  return res.status(204).end();
}

export async function requestPasswordReset(req: AuthedRequest, res: Response) {
  const ticket = await queuePasswordReset(req.body.email);
  return res.status(202).json({ ticket });
}

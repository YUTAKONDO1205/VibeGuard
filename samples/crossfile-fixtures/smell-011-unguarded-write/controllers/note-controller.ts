import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addNote, addShare, dropNote, editNote } from '../store';

export async function createNote(req: AuthedRequest, res: Response) {
  const created = await addNote(req.body);
  return res.status(201).json({ created });
}

export async function updateNote(req: AuthedRequest, res: Response) {
  const updated = await editNote(req.params.id, req.body.body);
  return res.json({ updated });
}

export async function removeNote(req: AuthedRequest, res: Response) {
  await dropNote(req.params.id);
  return res.status(204).end();
}

export async function shareNote(req: AuthedRequest, res: Response) {
  const shared = await addShare(req.params.id, req.body.recipient);
  return res.json({ shared });
}

import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addReport, dropReport, editReport } from '../store';

export async function createReport(req: AuthedRequest, res: Response) {
  const created = await addReport(req.body);
  return res.status(201).json({ created });
}

export async function updateReport(req: AuthedRequest, res: Response) {
  const updated = await editReport(req.params.id, req.body.title);
  return res.json({ updated });
}

export async function removeReport(req: AuthedRequest, res: Response) {
  await dropReport(req.params.id);
  return res.status(204).end();
}

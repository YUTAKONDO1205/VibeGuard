import type { Response } from 'express';
import type { AuthedRequest } from '../types';

// Inlined site 1 of 2.
export async function archiveProject(req: AuthedRequest, res: Response) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ id: req.params.id, archived: true });
}

export async function listProjects(_req: AuthedRequest, res: Response) {
  return res.json({ projects: [] });
}

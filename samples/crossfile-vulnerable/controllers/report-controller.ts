import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { collectReportRows } from '../data/store';

// Site 4 of four, and the one that shows the drift the smell is about: this
// handler accepts `superuser` as well, so the four inlined checks no longer
// describe the same policy. Nothing in the codebase can tell you that.
export async function exportReport(req: AuthedRequest, res: Response) {
  const actor = req.user;
  if (actor.role !== 'admin' && actor.role !== 'superuser') {
    return res.status(403).send();
  }

  const rows = await collectReportRows();
  return res.json({ generatedAt: new Date().toISOString(), rows });
}

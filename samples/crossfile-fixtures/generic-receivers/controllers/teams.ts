import type { Request, Response } from 'express';

export function archiveTeam(req: Request, res: Response) {
  const h = req.body.requester;
  if (h.role !== 'admin') return res.status(403).send();
  return res.json({ ok: true });
}

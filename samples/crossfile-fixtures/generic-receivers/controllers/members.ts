import type { Request, Response } from 'express';

export function auditMembers(req: Request, res: Response) {
  for (const entry of req.body.members) {
    if (entry.role !== 'admin') return res.status(403).send();
  }
  return res.json({ ok: true });
}

export function promoteMember(req: Request, res: Response) {
  const item = req.body.target;
  if (item.role !== 'admin') return res.status(403).send();
  return res.json({ ok: true });
}

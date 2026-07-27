import type { Request, Response } from 'express';

export function replay(req: Request, res: Response) {
  const turns = req.body.turns.filter((m: { role: string }) => m.role !== 'tool');
  return res.json({ turns });
}

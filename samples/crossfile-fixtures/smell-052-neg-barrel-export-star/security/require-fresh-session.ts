import type { NextFunction, Request, Response } from 'express';

export function requireFreshSession(req: Request, res: Response, next: NextFunction): void {
  const issued = Number(req.header('x-session-issued-at') ?? 0);
  if (!Number.isFinite(issued) || Date.now() - issued > 900_000) {
    res.status(401).json({ error: 'session expired' });
    return;
  }
  next();
}

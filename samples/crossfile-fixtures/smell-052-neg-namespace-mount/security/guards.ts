import type { NextFunction, Request, Response } from 'express';

export function requireOwnerScope(req: Request, res: Response, next: NextFunction): void {
  if (req.header('x-scope') !== 'owner') {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
}

export function requireFreshSession(req: Request, res: Response, next: NextFunction): void {
  const issued = Number(req.header('x-session-issued-at') ?? 0);
  if (!Number.isFinite(issued) || Date.now() - issued > 900_000) {
    res.status(401).json({ error: 'session expired' });
    return;
  }
  next();
}

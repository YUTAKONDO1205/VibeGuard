import type { NextFunction, Request, Response } from 'express';

export function requireAdminRole(req: Request, res: Response, next: NextFunction): void {
  if (req.header('x-role') !== 'admin') {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
}

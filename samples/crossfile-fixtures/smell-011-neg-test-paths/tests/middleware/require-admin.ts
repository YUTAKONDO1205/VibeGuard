import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';

export function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const user = req.user;
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

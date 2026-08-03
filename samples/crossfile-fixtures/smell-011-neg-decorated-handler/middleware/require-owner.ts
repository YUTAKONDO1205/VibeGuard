import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';

export function requireOwner(req: AuthedRequest, res: Response, next: NextFunction) {
  const user = req.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  if (user.role !== 'owner') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

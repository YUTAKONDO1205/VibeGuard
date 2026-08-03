import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';

export function requireLogin(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  return next();
}

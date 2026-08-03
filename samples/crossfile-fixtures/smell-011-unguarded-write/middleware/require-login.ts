import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';

// Authentication, not authorization: it establishes who the caller is and
// refuses anonymous requests. Three of this service's four writes name it.
export function requireLogin(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  return next();
}

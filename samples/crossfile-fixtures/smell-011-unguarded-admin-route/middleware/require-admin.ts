import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';

// The one place this service decides whether a caller may write. Routes that
// name it in the middleware position have their policy readable at the
// registration; routes that do not, do not.
export function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const user = req.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

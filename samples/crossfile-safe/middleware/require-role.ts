import type { NextFunction, Response } from 'express';
import type { AuthedRequest, SessionUser } from '../types';

// The single place in this service where a privilege decision is made. Every
// route that needs one names this guard in its middleware position, so the
// policy is one grep away and one edit away.
//
// It takes the allowed roles as arguments rather than hardcoding a comparison
// so that widening a route from `admin` to `admin, owner` is a change at the
// route registration, not a change inside a handler body.
export function requireRole(...allowed: Array<SessionUser['role']>) {
  return function roleGuard(req: AuthedRequest, res: Response, next: NextFunction) {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: 'unauthenticated' });
    }
    if (!allowed.includes(user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

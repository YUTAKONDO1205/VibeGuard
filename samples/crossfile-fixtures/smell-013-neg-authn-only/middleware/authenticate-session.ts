import type { AuthedRequest } from '../types';

// Authentication, not authorization: it establishes that there is a principal
// and refuses anonymous callers. It has no opinion about privilege.
export function authenticateSession(req: AuthedRequest, res: any, next: () => void) {
  if (!req.user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  return next();
}

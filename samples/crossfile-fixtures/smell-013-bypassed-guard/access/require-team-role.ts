import type { AuthedRequest, SessionUser } from '../types';

// The single place this service is supposed to decide privilege. Widening a
// route from admin to admin+owner is an edit at the registration, not inside a
// handler body.
export function requireTeamRole(...allowed: Array<SessionUser['role']>) {
  return function roleGuard(req: AuthedRequest, res: any, next: () => void) {
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

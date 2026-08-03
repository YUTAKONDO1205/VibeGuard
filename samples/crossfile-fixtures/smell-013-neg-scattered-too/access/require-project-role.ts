import type { AuthedRequest } from '../types';

export function requireProjectRole(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'maintainer') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

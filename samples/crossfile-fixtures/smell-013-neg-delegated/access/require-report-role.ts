import type { AuthedRequest } from '../types';

export function requireReportRole(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'analyst') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

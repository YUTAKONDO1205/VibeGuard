import type { AuthedRequest } from '../types';

export function requireLedgerRole(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'accountant') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

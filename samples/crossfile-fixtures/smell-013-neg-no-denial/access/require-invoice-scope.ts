import type { AuthedRequest } from '../types';

export function requireInvoiceScope(req: AuthedRequest, res: any, next: () => void) {
  if (!req.user.permissions.includes('invoice:read')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

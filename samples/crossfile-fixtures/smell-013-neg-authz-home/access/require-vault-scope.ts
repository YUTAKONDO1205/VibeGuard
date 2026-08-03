import type { AuthedRequest } from '../types';

export function requireVaultScope(req: AuthedRequest, res: any, next: () => void) {
  if (!req.user.permissions.includes('vault:read')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

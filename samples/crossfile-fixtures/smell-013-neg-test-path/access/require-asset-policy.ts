import type { AuthedRequest } from '../types';

export function requireAssetPolicy(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'curator') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

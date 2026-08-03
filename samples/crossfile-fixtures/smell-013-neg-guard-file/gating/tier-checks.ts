import type { AuthedRequest } from '../types';

export function requireTierPolicy(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

// A route handler that lives in the same file as the guard. Authorization
// written here is authorization written where it belongs.
export async function tierStatus(req: AuthedRequest, res: any) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ tier: 'gold' });
}

import type { AuthedRequest } from '../types';

// Registered as a route handler, but it lives in the authorization layer.
export async function rotateVaultKey(req: AuthedRequest, res: any) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ rotated: true });
}

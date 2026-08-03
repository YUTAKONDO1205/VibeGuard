import type { AuthedRequest } from '../types';

export async function removeLabel(req: AuthedRequest, res: any) {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ removed: req.params.id });
}

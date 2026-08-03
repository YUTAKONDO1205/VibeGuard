import type { AuthedRequest } from '../types';

export function requireDocumentRole(req: AuthedRequest, res: any, next: () => void) {
  if (req.user.role !== 'editor') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

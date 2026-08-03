import type { AuthedRequest } from '../types';

export function requireThreadPermission(req: AuthedRequest, res: any, next: () => void) {
  if (!req.user.permissions.includes('thread:write')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

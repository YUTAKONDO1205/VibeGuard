import type { AuthedRequest } from '../types';

export function requireBillingPermission(scope: string) {
  return function permissionGuard(req: AuthedRequest, res: any, next: () => void) {
    if (!req.user.permissions.includes(scope)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

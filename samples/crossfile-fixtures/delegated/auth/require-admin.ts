import type { Request } from 'express';

// The one comparison in this fixture. It is inside a named, exported helper
// that every handler calls — the check has a name, a home, and a single edit
// site, which is what condition (b) of §7.2 is asking about.
export interface AuthedRequest extends Request {
  user?: { id: string; role: string };
}

export class ForbiddenError extends Error {
  readonly status = 403;
}

export function requireAdmin(req: AuthedRequest): void {
  const user = req.user;
  if (!user || user.role !== 'admin') {
    throw new ForbiddenError('forbidden');
  }
}

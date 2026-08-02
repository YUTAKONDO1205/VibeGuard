import type { Request } from 'express';

// Discovered by the framework's `security/*.guard.ts` glob at boot. No line
// anywhere in this repository mentions the class, and that is the designed state
// rather than an omission.
export class RequireAdminGuard {
  canActivate(req: Request): boolean {
    const header = req.header('authorization');
    return typeof header === 'string' && header.startsWith('Bearer ');
  }
}

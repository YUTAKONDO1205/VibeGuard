import type { Request } from 'express';

// The session shape the upstream authentication middleware attaches. Note that
// AUTHENTICATION (who are you) is centralised — it is only AUTHORIZATION (are
// you allowed) that each handler re-decides for itself.
export interface SessionUser {
  id: string;
  email: string;
  role: 'admin' | 'owner' | 'superuser' | 'member' | 'viewer';
  isAdmin: boolean;
}

export interface AuthedRequest extends Request {
  user: SessionUser;
}

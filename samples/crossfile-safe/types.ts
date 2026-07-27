import type { Request } from 'express';

export interface SessionUser {
  id: string;
  email: string;
  role: 'admin' | 'owner' | 'superuser' | 'member' | 'viewer';
}

export interface AuthedRequest extends Request {
  user: SessionUser;
}

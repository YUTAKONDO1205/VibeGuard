import type { Request } from 'express';

export interface SessionUser {
  id: string;
  email: string;
  role: 'admin' | 'owner' | 'member';
}

export interface AuthedRequest extends Request {
  user?: SessionUser;
}

import type { Request } from 'express';

export interface SessionUser {
  id: string;
  role: 'admin' | 'member';
}

export interface AuthedRequest extends Request {
  user?: SessionUser;
}

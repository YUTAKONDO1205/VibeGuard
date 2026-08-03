import type { Request } from 'express';

export interface SessionUser {
  id: string;
  email: string;
}

export interface AuthedRequest extends Request {
  user?: SessionUser;
}

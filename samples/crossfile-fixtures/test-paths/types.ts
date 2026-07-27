import type { Request } from 'express';

export interface AuthedRequest extends Request {
  user: { id: string; role: string };
}

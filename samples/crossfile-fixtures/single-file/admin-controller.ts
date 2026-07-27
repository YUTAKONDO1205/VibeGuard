import { Router } from 'express';
import type { Response } from 'express';
import type { AuthedRequest } from './types';

// Three inlined checks, three route handlers, ONE file. Everything the
// cross-file rule needs except the "multiple files" half of condition (a).
export const adminRouter = Router();

adminRouter.get('/flags', async (req: AuthedRequest, res: Response) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ flags: [] });
});

adminRouter.post('/flags', async (req: AuthedRequest, res: Response) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.status(201).json({ created: true });
});

adminRouter.delete('/flags/:key', async (req: AuthedRequest, res: Response) => {
  if (req.user.role !== 'superuser') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.status(204).end();
});

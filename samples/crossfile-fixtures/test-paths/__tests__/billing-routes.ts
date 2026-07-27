import { Router } from 'express';
import type { Response } from 'express';
import type { AuthedRequest } from '../types';

export function buildBillingTestRouter() {
  const router = Router();
  router.get('/invoices', (req: AuthedRequest, res: Response) => {
    if (req.user.role !== 'owner') {
      return res.status(403).json({ error: 'forbidden' });
    }
    return res.json({ invoices: [] });
  });
  return router;
}

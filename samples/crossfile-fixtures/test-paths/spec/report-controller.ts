import { Router } from 'express';
import type { Response } from 'express';
import type { AuthedRequest } from '../types';

// Third site, reached through the `spec/` directory convention rather than
// `__tests__/`, so the exclusion is exercised on two different path segments
// and not just on one hardcoded directory name.
export function buildReportSpecRouter() {
  const router = Router();
  router.post('/reports/export', (req: AuthedRequest, res: Response) => {
    if (req.user.role !== 'superuser') {
      return res.status(403).json({ error: 'forbidden' });
    }
    return res.json({ rows: [] });
  });
  return router;
}

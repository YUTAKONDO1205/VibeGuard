import { Router } from 'express';
import type { Response } from 'express';
import type { AuthedRequest } from '../types';

// A hand-rolled harness router built for the user-routes suite. The check is
// inlined here on purpose: the suite asserts the 403 branch without booting the
// real middleware, which is the correct thing for a test to do.
export function buildUserTestRouter() {
  const router = Router();
  router.get('/users', (req: AuthedRequest, res: Response) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    return res.json({ users: [] });
  });
  return router;
}

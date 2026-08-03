import { Router } from 'express';
import type { AuthedRequest } from '../types';

// A harness route used by the integration tests. It re-derives the privilege
// decision on purpose, so the tests can exercise both branches without booting
// the real guard.
export const harnessRouter = Router();

export async function harnessProbe(req: AuthedRequest, res: any) {
  if (req.user.role !== 'curator') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ ok: true });
}

harnessRouter.get('/probe', harnessProbe);

import { Router } from 'express';
import type { NextFunction, Response } from 'express';
import type { AuthedRequest } from '../types';
import { purgeArchived } from '../store';
import { createReport, removeReport, updateReport } from '../controllers/report-controller';

// The guard lives in the file that registers the routes, so everything this
// finding would say is visible by reading one file.
export function requireOwner(req: AuthedRequest, res: Response, next: NextFunction) {
  const user = req.user;
  if (!user || user.role !== 'owner') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

export async function purgeReports(_req: AuthedRequest, res: Response) {
  const removed = await purgeArchived();
  return res.json({ removed });
}

export const reportRouter = Router();

reportRouter.post('/reports', requireOwner, createReport);
reportRouter.put('/reports/:id', requireOwner, updateReport);
reportRouter.delete('/reports/:id', requireOwner, removeReport);
reportRouter.post('/reports/purge', purgeReports);

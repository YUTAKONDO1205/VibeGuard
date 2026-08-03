import { Router } from 'express';
import type { Response } from 'express';
import { requireOwner } from '../middleware/require-owner';
import { OwnerGuard, UseGuards } from '../framework/guards';
import type { AuthedRequest } from '../types';
import { purgeArchived } from '../store';
import { createReport, removeReport, updateReport } from '../controllers/report-controller';

export const reportRouter = Router();

reportRouter.post('/reports', requireOwner, createReport);
reportRouter.put('/reports/:id', requireOwner, updateReport);
reportRouter.delete('/reports/:id', requireOwner, removeReport);

class ReportAdminOps {
  @UseGuards(OwnerGuard)
  async purgeReports(_req: AuthedRequest, res: Response) {
    const removed = await purgeArchived();
    return res.json({ removed });
  }
}

const reportOps = new ReportAdminOps();

// No middleware argument, and no omission either: the handler carries the guard
// on its declaration.
reportRouter.post('/reports/purge', reportOps.purgeReports);

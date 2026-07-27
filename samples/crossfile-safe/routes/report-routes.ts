import { Router } from 'express';
import { requireRole } from '../middleware/require-role';
import { exportReport } from '../controllers/report-controller';

// The one route whose policy differs is expressed by widening the guard's
// arguments, not by re-deciding inside the handler.
export const reportRouter = Router();

reportRouter.post('/export', requireRole('admin', 'superuser'), exportReport);

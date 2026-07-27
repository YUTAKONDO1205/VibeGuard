import { Router } from 'express';
import { exportReport } from '../controllers/report-controller';

export const reportRouter = Router();

reportRouter.post('/export', exportReport);

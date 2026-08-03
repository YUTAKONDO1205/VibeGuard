import { Router } from 'express';
import { requireReportRole } from '../access/require-report-role';
import { listReports, purgeReports, runReport, scheduleReport } from '../controllers/report-controller';

export const reportRouter = Router();

reportRouter.get('/', requireReportRole, listReports);
reportRouter.post('/run', requireReportRole, runReport);
reportRouter.post('/schedule', requireReportRole, scheduleReport);

reportRouter.delete('/purge', purgeReports);

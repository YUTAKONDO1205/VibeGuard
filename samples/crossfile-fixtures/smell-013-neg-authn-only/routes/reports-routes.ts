import { Router } from 'express';
import { authenticateSession } from '../middleware/authenticate-session';
import { archiveReport, exportReports, listReports, purgeReports } from '../controllers/reports-controller';

export const reportsRouter = Router();

reportsRouter.get('/', authenticateSession, listReports);
reportsRouter.get('/export', authenticateSession, exportReports);
reportsRouter.post('/:id/archive', authenticateSession, archiveReport);
reportsRouter.delete('/purge', authenticateSession, purgeReports);

import { Router } from 'express';
import { listOrders } from './controllers/orders-controller';
import { renameTeam } from './controllers/teams-controller';
import { readAuditLog, purgeAuditLog } from './controllers/audit-controller';

export const apiRouter = Router();

apiRouter.get('/orders', listOrders);
apiRouter.patch('/teams/:id', renameTeam);
apiRouter.get('/audit', readAuditLog);
apiRouter.delete('/audit', purgeAuditLog);

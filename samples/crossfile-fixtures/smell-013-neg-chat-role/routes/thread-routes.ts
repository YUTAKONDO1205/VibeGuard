import { Router } from 'express';
import { requireThreadPermission } from '../access/require-thread-permission';
import { appendTurn, deleteThread, listThreads, showThread } from '../controllers/thread-controller';

export const threadRouter = Router();

threadRouter.get('/', requireThreadPermission, listThreads);
threadRouter.get('/:id', requireThreadPermission, showThread);
threadRouter.delete('/:id', requireThreadPermission, deleteThread);

threadRouter.post('/:id/turns', appendTurn);

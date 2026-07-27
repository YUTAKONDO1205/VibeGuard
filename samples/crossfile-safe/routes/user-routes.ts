import { Router } from 'express';
import { requireRole } from '../middleware/require-role';
import { listUsers, deleteUser } from '../controllers/user-controller';

// The guard sits in the middleware position, ahead of the handler. Reading this
// file tells you the whole authorization policy for /api/users.
export const userRouter = Router();

userRouter.get('/', requireRole('admin'), listUsers);
userRouter.delete('/:id', requireRole('admin'), deleteUser);

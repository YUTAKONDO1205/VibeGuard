import { Router } from 'express';
import { listUsers, deleteUser } from '../controllers/user-controller';

// Two handlers, registered with no guard in the middleware position. The
// authorization decision for both lives inside `user-controller.ts`.
export const userRouter = Router();

userRouter.get('/', listUsers);
userRouter.delete('/:id', deleteUser);

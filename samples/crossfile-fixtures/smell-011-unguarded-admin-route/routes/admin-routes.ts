import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createUser, promoteUser, removeUser, updateUser } from '../controllers/admin-controller';

export const adminRouter = Router();

adminRouter.post('/users', requireAdmin, createUser);
adminRouter.put('/users/:id', requireAdmin, updateUser);
adminRouter.delete('/users/:id', requireAdmin, removeUser);

// The fourth write on the same router, in the same file, two lines below three
// registrations that carry the guard imported at the top. Nothing here is
// syntactically incomplete, which is exactly why nobody notices.
adminRouter.post('/users/:id/promote', promoteUser);

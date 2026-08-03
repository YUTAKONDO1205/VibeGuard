import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createAccount, removeAccount, renameAccount, updateAccount } from '../controllers/account-controller';

export const accountRouter = Router();

accountRouter.post('/accounts', requireAdmin, createAccount);
accountRouter.put('/accounts/:id', requireAdmin, updateAccount);
accountRouter.delete('/accounts/:id', requireAdmin, removeAccount);

// Renaming your own account needs no admin privilege, only a session — and the
// session check is mounted for the whole application in app.ts.
accountRouter.patch('/accounts/:id/name', renameAccount);

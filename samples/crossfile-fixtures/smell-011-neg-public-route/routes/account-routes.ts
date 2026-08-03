import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createAccount, removeAccount, requestPasswordReset, updateAccount } from '../controllers/account-controller';

export const accountRouter = Router();

accountRouter.post('/accounts', requireAdmin, createAccount);
accountRouter.put('/accounts/:id', requireAdmin, updateAccount);
accountRouter.delete('/accounts/:id', requireAdmin, removeAccount);

// Unguarded on purpose, and correct: a caller who has forgotten their password
// cannot authenticate, so nothing may stand between them and this endpoint.
accountRouter.post('/password/reset', requestPasswordReset);

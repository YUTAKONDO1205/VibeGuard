import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { updateTenant } from '../controllers/tenant-controller';

// A second file applying the same guard, which is what makes the convention a
// project decision rather than one router's local habit.
export const tenantRouter = Router();

tenantRouter.put('/settings', requireAdmin, updateTenant);

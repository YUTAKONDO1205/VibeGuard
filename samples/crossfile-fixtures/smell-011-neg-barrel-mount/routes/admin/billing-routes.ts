import { Router } from 'express';
import { requireOwner } from '../../middleware/require-owner';
import { createCharge, issueRefund, removeCharge, updateCharge } from '../../controllers/charge-controller';

export const billingRouter = Router();

billingRouter.post('/charges', requireOwner, createCharge);
billingRouter.put('/charges/:id', requireOwner, updateCharge);
billingRouter.delete('/charges/:id', requireOwner, removeCharge);

// Unguarded here, and behind `requireAdmin` at the mount — which app.ts reaches
// through the barrel next door, not through an import of this file.
billingRouter.post('/charges/:id/refund', issueRefund);

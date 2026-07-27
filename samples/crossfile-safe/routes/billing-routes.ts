import { Router } from 'express';
import { requireRole } from '../middleware/require-role';
import { getInvoice } from '../controllers/billing-controller';

export const billingRouter = Router();

billingRouter.get('/invoices/:id', requireRole('owner'), getInvoice);

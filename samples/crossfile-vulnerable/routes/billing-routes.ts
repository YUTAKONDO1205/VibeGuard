import { Router } from 'express';
import { getInvoice } from '../controllers/billing-controller';

export const billingRouter = Router();

billingRouter.get('/invoices/:id', getInvoice);

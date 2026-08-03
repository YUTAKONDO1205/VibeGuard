import { Router } from 'express';
import { requireBillingPermission } from '../access/require-billing-permission';
import { closePeriod, listCharges, refundCharge, sendInvoice } from '../controllers/billing-controller';

export const billingRouter = Router();

billingRouter.get('/charges', requireBillingPermission('billing:read'), listCharges);
billingRouter.post('/charges/:id/refund', requireBillingPermission('billing:write'), refundCharge);
billingRouter.post('/periods/close', requireBillingPermission('billing:write'), closePeriod);

billingRouter.post('/invoices/send', sendInvoice);

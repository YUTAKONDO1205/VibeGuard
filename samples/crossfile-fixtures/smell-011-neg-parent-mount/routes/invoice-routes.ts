import { Router } from 'express';
import { requireOwner } from '../middleware/require-owner';
import { cancelInvoice, createInvoice, removeInvoice, updateInvoice } from '../controllers/invoice-controller';

export const invoiceRouter = Router();

invoiceRouter.post('/invoices', requireOwner, createInvoice);
invoiceRouter.put('/invoices/:id', requireOwner, updateInvoice);
invoiceRouter.delete('/invoices/:id', requireOwner, removeInvoice);

// No per-route guard, and none is needed: this router is mounted behind
// `requireAdmin` in app.ts, so nothing reaches it without that check first.
invoiceRouter.post('/invoices/:id/cancel', cancelInvoice);

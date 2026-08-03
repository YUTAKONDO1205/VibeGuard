import { Router } from 'express';
import { requireInvoiceScope } from '../access/require-invoice-scope';
import { cancelInvoice, createInvoice, listInvoices, showInvoice } from '../controllers/invoice-controller';

export const invoiceRouter = Router();

invoiceRouter.get('/:id', requireInvoiceScope, showInvoice);
invoiceRouter.post('/', requireInvoiceScope, createInvoice);
invoiceRouter.post('/:id/cancel', requireInvoiceScope, cancelInvoice);

invoiceRouter.get('/', listInvoices);

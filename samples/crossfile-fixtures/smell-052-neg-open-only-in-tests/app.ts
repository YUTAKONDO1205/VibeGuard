import express from 'express';
import { requireAdminRole } from './security/require-admin-role';
import { listInvoices } from './routes/invoices';

const app = express();

app.use(express.json());

app.get('/invoices', requireAdminRole, listInvoices);

export { app };

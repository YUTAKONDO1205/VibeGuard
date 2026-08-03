import express from 'express';
import { requireAdmin } from './middleware/require-admin';
import { invoiceRouter } from './routes/invoice-routes';

const app = express();

app.use(express.json());

// A targeted mount: the guard has a router after it, so what it protects is
// knowable — everything `invoiceRouter` can reach.
app.use('/admin', requireAdmin, invoiceRouter);

export { app };

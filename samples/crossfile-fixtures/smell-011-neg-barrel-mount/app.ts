import express from 'express';
import { requireAdmin } from './middleware/require-admin';
import { billingRouter } from './routes/admin';

const app = express();

app.use(express.json());
app.use('/admin', requireAdmin, billingRouter);

export { app };

import express from 'express';
import { listInvoices } from './routes/invoices';

const app = express();

app.use(express.json());

app.get('/invoices', listInvoices);

export { app };

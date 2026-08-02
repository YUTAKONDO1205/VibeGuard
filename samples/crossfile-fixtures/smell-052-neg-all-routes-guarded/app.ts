import express from 'express';
import { requireAdmin } from './security/require-admin';
import { createReport, listReports } from './routes/reports';

const app = express();

app.use(express.json());
app.use(requireAdmin);
app.use('/reports', requireAdmin);

app.get('/reports', requireAdmin, listReports);
app.post('/reports', requireAdmin, createReport);

export { app };

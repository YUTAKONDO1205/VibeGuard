import express from 'express';
import { listReports } from './routes/reports';

const app = express();

app.use(express.json());

app.get('/reports', listReports);

export { app };

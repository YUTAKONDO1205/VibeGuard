import express from 'express';
import { reportRouter } from './routes/report-routes';

const app = express();

app.use(express.json());
app.use('/api', reportRouter);

export { app };

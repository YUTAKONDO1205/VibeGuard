import express from 'express';
import { listStatuses } from './routes/status';

const app = express();

app.use(express.json());

app.get('/status', listStatuses);

export { app };

import express from 'express';
import { listRegions, listStatus } from './routes/status';

const app = express();

app.use(express.json());

app.get('/status', listStatus);
app.get('/regions', listRegions);

export { app };

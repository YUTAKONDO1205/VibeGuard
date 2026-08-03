import express from 'express';
import { accountRouter } from './routes/account-routes';

const app = express();

app.use(express.json());
app.use('/api', accountRouter);

export { app };

import express from 'express';
import { userRouter } from './routes/user-routes';
import { billingRouter } from './routes/billing-routes';
import { reportRouter } from './routes/report-routes';

const app = express();

app.use(express.json());

app.use('/api/users', userRouter);
app.use('/api/billing', billingRouter);
app.use('/api/reports', reportRouter);

app.listen(Number(process.env.PORT ?? 3000));

export { app };

import express from 'express';
import { orderRouter } from './routes/order-routes';

const app = express();

app.use(express.json());
app.use('/api', orderRouter);

export { app };

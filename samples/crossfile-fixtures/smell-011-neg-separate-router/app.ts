import express from 'express';
import { feedbackRouter } from './routes/feedback-routes';
import { orderRouter } from './routes/order-routes';

const app = express();

app.use(express.json());
app.use('/api', orderRouter);
app.use('/api', feedbackRouter);

export { app };

import express from 'express';
import passport from 'passport';
import { orderRouter } from './routes/order-routes';

const app = express();

app.use(express.json());
app.use(passport.initialize());
app.use('/api', orderRouter);

export { app };

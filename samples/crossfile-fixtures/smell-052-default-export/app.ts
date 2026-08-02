import express from 'express';
import { searchOrders } from './routes/search';

const app = express();

app.use(express.json());

app.get('/orders', searchOrders);

export { app };

import express from 'express';
import { renderProfile } from './routes/a-profile';
import { searchOrders } from './routes/b-search';

const app = express();

app.use(express.json());

app.get('/profile', renderProfile);
app.get('/orders', searchOrders);

export { app };

import express from 'express';
import { searchProducts } from './routes/search';

const app = express();

app.use(express.json());

app.get('/search', searchProducts);

export { app };

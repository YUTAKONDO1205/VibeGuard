import express from 'express';
import { requestLogger } from './middleware/request-logger';
import { searchProducts } from './routes/search';
import { listCategories } from './routes/categories';

const app = express();

app.use(express.json());
app.use(requestLogger);

app.get('/search', searchProducts);
app.get('/categories', listCategories);

export { app };

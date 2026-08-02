import express from 'express';
import { readArticle } from './routes/articles';

const app = express();

app.use(express.json());

app.get('/articles/:slug', readArticle);

export { app };

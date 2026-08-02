import express from 'express';
import { createComment } from './routes/comments';

const app = express();

app.use(express.json());

app.post('/comments', createComment);

export { app };

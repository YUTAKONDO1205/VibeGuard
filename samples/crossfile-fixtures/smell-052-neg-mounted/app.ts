import express from 'express';
import { validateInput } from './middleware/validate-input';
import { createComment, listComments } from './routes/comments';

const app = express();

app.use(express.json());

app.post('/comments', validateInput, createComment);
app.get('/comments', listComments);

export { app };

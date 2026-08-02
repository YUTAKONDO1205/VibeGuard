import express from 'express';
import { createAccount } from './routes/signup';

const app = express();

app.use(express.json());

app.post('/signup', createAccount);

export { app };

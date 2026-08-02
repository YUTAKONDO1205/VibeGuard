import express from 'express';
import { createUpload } from './routes/uploads';

const app = express();

app.use(express.json());

app.post('/uploads', createUpload);

export { app };

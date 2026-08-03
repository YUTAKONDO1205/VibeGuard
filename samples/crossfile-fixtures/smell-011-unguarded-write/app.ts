import express from 'express';
import { noteRouter } from './routes/note-routes';

const app = express();

app.use(express.json());
app.use('/api', noteRouter);

export { app };

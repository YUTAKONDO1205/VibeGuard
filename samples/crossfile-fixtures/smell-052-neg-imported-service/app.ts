import express from 'express';
import { listRooms } from './routes/rooms';

const app = express();

app.use(express.json());

app.get('/rooms', listRooms);

export { app };

import express from 'express';
import { db } from './db';

const app = express();

app.use(express.json());

function sanitizeUserInput(raw: string): string {
  return raw.replace(/[<>"'`]/g, '');
}

app.post('/comments', async (req, res) => {
  const text = req.body.text;
  await db.query(`INSERT INTO comments (body) VALUES ('${text}')`);
  res.status(201).end();
});

export { app, sanitizeUserInput };

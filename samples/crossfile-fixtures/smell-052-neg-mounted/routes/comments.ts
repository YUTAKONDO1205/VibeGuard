import type { Request, Response } from 'express';
import { db } from '../db';

export async function createComment(req: Request, res: Response): Promise<void> {
  const text = req.body.text;
  await db.query(`INSERT INTO comments (body) VALUES ('${text}')`);
  res.status(201).end();
}

export async function listComments(_req: Request, res: Response): Promise<void> {
  const rows = await db.query('SELECT id, body FROM comments ORDER BY id DESC');
  res.json({ rows });
}

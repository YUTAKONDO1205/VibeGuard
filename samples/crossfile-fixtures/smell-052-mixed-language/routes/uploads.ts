import type { Request, Response } from 'express';
import { db } from '../db';

export async function createUpload(req: Request, res: Response): Promise<void> {
  const filename = req.body.filename;
  await db.query(`INSERT INTO uploads (filename) VALUES ('${filename}')`);
  res.status(201).end();
}

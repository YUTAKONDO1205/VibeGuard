import type { Request, Response } from 'express';
import { db } from '../db';

export async function createAccount(req: Request, res: Response): Promise<void> {
  const email = req.body.email;
  await db.query(`INSERT INTO accounts (email) VALUES ('${email}')`);
  res.status(201).end();
}

import type { Request, Response } from 'express';
import { db } from '../db';

export async function searchIncidents(req: Request, res: Response): Promise<void> {
  const term = req.query.q;
  const rows = await db.query(`SELECT id, title FROM incidents WHERE title LIKE '%${term}%'`);
  res.json({ rows });
}

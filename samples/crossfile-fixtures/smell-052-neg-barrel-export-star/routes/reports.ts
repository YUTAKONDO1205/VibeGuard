import type { Request, Response } from 'express';
import { db } from '../db';

export async function listReports(req: Request, res: Response): Promise<void> {
  const owner = req.query.owner;
  const rows = await db.query(`SELECT id, title FROM reports WHERE owner = '${owner}'`);
  res.json({ rows });
}

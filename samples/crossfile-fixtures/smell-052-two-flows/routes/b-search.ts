import type { Request, Response } from 'express';
import { db } from '../db';

export async function searchOrders(req: Request, res: Response): Promise<void> {
  const term = req.query.q;
  const rows = await db.query(`SELECT id, note FROM orders WHERE note LIKE '%${term}%'`);
  res.json({ rows });
}

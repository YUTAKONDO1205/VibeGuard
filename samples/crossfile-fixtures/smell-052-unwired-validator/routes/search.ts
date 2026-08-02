import type { Request, Response } from 'express';
import { db } from '../db';

export async function searchProducts(req: Request, res: Response): Promise<void> {
  const term = req.query.q;
  const rows = await db.query(`SELECT id, name FROM products WHERE name LIKE '%${term}%'`);
  res.json({ rows });
}

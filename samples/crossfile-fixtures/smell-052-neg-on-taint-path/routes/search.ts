import type { Request, Response } from 'express';
import { db } from '../db';
import { sanitizeSearchTerm } from '../security/sanitize-search-term';

export async function searchProducts(req: Request, res: Response): Promise<void> {
  const raw = req.query.q;
  const term = sanitizeSearchTerm(raw);
  const rows = await db.query(`SELECT id, name FROM products WHERE name LIKE '%${term}%'`);
  res.json({ rows });
}

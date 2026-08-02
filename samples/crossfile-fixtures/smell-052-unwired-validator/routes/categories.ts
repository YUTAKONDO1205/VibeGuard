import type { Request, Response } from 'express';
import { db } from '../db';

export async function listCategories(_req: Request, res: Response): Promise<void> {
  const rows = await db.query('SELECT id, name FROM categories ORDER BY name');
  res.json({ rows });
}

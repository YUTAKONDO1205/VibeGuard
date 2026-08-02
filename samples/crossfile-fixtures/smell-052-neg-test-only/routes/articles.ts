import type { Request, Response } from 'express';
import { db } from '../db';

export async function readArticle(req: Request, res: Response): Promise<void> {
  const slug = req.params.slug;
  const rows = await db.query(`SELECT id, body FROM articles WHERE slug = '${slug}'`);
  res.json({ rows });
}

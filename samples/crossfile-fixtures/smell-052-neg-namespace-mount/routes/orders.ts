import type { Request, Response } from 'express';
import { db } from '../db';

export async function listOrders(req: Request, res: Response): Promise<void> {
  const owner = req.query.owner;
  const rows = await db.query(`SELECT id, total FROM orders WHERE owner = '${owner}'`);
  res.json({ rows });
}

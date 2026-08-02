import type { Request, Response } from 'express';
import { db } from '../db';

export async function listRooms(req: Request, res: Response): Promise<void> {
  const owner = req.query.owner;
  const rows = await db.query(`SELECT id, name FROM rooms WHERE owner = '${owner}'`);
  res.json({ rows });
}

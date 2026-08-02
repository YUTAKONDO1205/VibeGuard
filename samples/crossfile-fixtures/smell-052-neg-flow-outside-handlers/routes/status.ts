import type { Request, Response } from 'express';
import { db } from '../db';

// The one registered handler, and it reads nothing a client controls.
export async function listStatuses(_req: Request, res: Response): Promise<void> {
  const rows = await db.query('SELECT component, state FROM health ORDER BY component');
  res.json({ rows });
}

import type { Request, Response } from 'express';
import { db } from '../db';

export async function listStatus(_req: Request, res: Response): Promise<void> {
  const rows = await db.query('SELECT service, state FROM health ORDER BY service');
  res.send(JSON.stringify(rows));
}

export async function listRegions(_req: Request, res: Response): Promise<void> {
  const rows = await db.query('SELECT code FROM regions ORDER BY code');
  res.send(JSON.stringify(rows));
}

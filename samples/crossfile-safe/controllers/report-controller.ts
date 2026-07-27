import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { collectReportRows } from '../data/store';

export async function exportReport(_req: AuthedRequest, res: Response) {
  const rows = await collectReportRows();
  return res.json({ generatedAt: new Date().toISOString(), rows });
}

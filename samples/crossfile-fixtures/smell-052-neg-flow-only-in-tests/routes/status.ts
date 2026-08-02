import type { Request, Response } from 'express';

export function listStatuses(_req: Request, res: Response): void {
  res.json({ status: 'ok', components: ['api', 'worker'] });
}

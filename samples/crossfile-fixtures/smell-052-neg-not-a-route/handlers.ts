import type { Request, Response } from 'express';

// Resolved by name at registration time, which is why the `app.get` above has no
// handler identifier for the indexer to record.
export const handlers: Record<string, (req: Request, res: Response) => void> = {
  listIncidents(_req: Request, res: Response): void {
    res.json({ incidents: [] });
  },
};

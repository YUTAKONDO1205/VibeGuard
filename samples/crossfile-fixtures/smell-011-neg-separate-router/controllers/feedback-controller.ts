import type { Request, Response } from 'express';

const received: string[] = [];

export async function submitFeedback(req: Request, res: Response) {
  received.push(String(req.body?.message ?? ''));
  return res.status(202).json({ queued: received.length });
}

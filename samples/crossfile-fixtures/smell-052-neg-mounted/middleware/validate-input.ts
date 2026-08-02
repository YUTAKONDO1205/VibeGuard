import type { NextFunction, Request, Response } from 'express';

export function validateInput(req: Request, res: Response, next: NextFunction): void {
  const text = req.body?.text;
  if (typeof text !== 'string' || text.length === 0 || text.length > 500) {
    res.status(400).json({ error: 'invalid comment' });
    return;
  }
  next();
}

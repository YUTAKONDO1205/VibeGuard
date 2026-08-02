import type { NextFunction, Request, Response } from 'express';

export function validateInput(req: Request, res: Response, next: NextFunction): void {
  const slug = req.params.slug;
  if (typeof slug !== 'string' || !/^[a-z0-9-]{1,80}$/.test(slug)) {
    res.status(400).json({ error: 'invalid slug' });
    return;
  }
  next();
}

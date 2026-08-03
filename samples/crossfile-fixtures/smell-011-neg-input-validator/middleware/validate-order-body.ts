import type { NextFunction, Request, Response } from 'express';

// A real middleware, applied consistently, and not an authorization boundary:
// it decides whether the REQUEST is well-formed, never whether the CALLER is
// allowed. Nothing it can do makes an unguarded route a defect.
export function validateOrderBody(req: Request, res: Response, next: NextFunction) {
  const quantity = Number(req.body?.quantity);
  if (!Number.isInteger(quantity) || quantity < 1) {
    return res.status(400).json({ error: 'quantity must be a positive integer' });
  }
  return next();
}

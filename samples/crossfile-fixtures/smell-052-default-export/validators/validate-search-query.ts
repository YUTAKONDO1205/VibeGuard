import type { NextFunction, Request, Response } from 'express';

/**
 * Generated alongside the orders endpoint and exported as the module default,
 * which is the shape a one-function module usually takes. Nothing imports it.
 */
export default function validateSearchQuery(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const term = req.query.q;
  if (typeof term !== 'string' || term.length > 64 || /[^\w \-]/.test(term)) {
    res.status(400).json({ error: 'invalid search term' });
    return;
  }
  next();
}

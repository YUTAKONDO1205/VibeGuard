import type { NextFunction, Request, Response } from 'express';

/**
 * Generated with the search endpoint and never mounted.
 *
 * Nothing is wrong with this function. It is exported, it is correct, and it is
 * the reason a reviewer skimming the diff concludes the search endpoint is
 * validated. The defect is entirely in what is absent from `app.ts`.
 */
export function validateInput(req: Request, res: Response, next: NextFunction): void {
  const term = req.query.q;
  if (typeof term !== 'string' || term.length > 64 || /[^\w \-]/.test(term)) {
    res.status(400).json({ error: 'invalid search term' });
    return;
  }
  next();
}

import type { NextFunction, Request, Response } from 'express';

// Generated, exported, mounted nowhere, referenced nowhere. The only reason this
// is not a finding is that nothing in this service reads client input at all.
export function validateInput(req: Request, res: Response, next: NextFunction): void {
  if (Object.keys(req.query).length > 0) {
    res.status(400).json({ error: 'no parameters accepted' });
    return;
  }
  next();
}

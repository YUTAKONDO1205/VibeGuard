import type { NextFunction, Request, Response } from 'express';

export function validateUploadPayload(req: Request, res: Response, next: NextFunction): void {
  const filename = req.body?.filename;
  if (typeof filename !== 'string' || filename.length === 0 || filename.includes('/')) {
    res.status(400).json({ error: 'invalid filename' });
    return;
  }
  next();
}

import type { NextFunction, Request, Response } from 'express';

// Not exported. Written for a mount that was never added, and unreachable from
// anywhere else in the process even if someone wanted to add it.
function validateCommentBody(req: Request, res: Response, next: NextFunction): void {
  const text = req.body?.text;
  if (typeof text !== 'string' || text.length === 0 || text.length > 500) {
    res.status(400).json({ error: 'invalid comment' });
    return;
  }
  next();
}

function logRejection(reason: string): void {
  process.stderr.write(`rejected: ${reason}\n`);
}

export { logRejection };

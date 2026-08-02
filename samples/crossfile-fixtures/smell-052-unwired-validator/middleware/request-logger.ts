import type { NextFunction, Request, Response } from 'express';

// Mounted, and deliberately not a security symbol: it exists so the fixture
// contains an `app.use(namedFunction)` registration whose handler slot is
// filled. That is the shape a rule looking for "a route with no guard" must not
// mistake for one.
export function requestLogger(req: Request, _res: Response, next: NextFunction): void {
  process.stdout.write(`${req.method} ${req.path}\n`);
  next();
}

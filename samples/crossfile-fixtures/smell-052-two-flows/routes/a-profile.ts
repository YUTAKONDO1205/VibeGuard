import type { Request, Response } from 'express';

export function renderProfile(req: Request, res: Response): void {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
}

import type { Request, Response } from 'express';

const priceBook: Array<{ sku: string; cents: number }> = [];

// Site 3 of three, in a second file so the two-file condition is satisfied.
export function getPriceBook(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  return res.json({ prices: priceBook.slice() });
}

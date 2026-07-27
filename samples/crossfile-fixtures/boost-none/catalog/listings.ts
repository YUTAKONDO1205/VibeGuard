import type { Request, Response } from 'express';

const listings: Array<{ id: string; title: string }> = [];

// Sites 1 and 2 of three. The compared value is `editor`, not `admin` — so the
// ELEVATED word test does not fire — and the handler only reads.
export function listListings(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  return res.json({ listings: listings.slice() });
}

export function getListing(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  const found = listings.find((l) => l.id === req.params.id);
  return found ? res.json(found) : res.status(404).send();
}

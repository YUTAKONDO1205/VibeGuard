import type { Request, Response } from 'express';
import { listingCollection } from '../db';

// Sites 1 and 2 of three. Byte-for-byte the same authorization check as
// `boost-none/catalog/listings.ts` — `editor`, not `admin` — and the same
// directory name, so the ONLY difference between the two fixtures is the
// mutating call that follows the check.
export async function renameListing(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  await listingCollection.updateOne({ id: req.params.id }, { $set: { title: req.body.title } });
  return res.status(204).end();
}

export async function retireListing(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  await listingCollection.deleteOne({ id: req.params.id });
  return res.status(204).end();
}

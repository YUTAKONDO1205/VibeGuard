import type { AuthedRequest } from '../types';

export async function listEntries(_req: AuthedRequest, res: any) {
  return res.json({ entries: [] });
}

export async function postEntry(req: AuthedRequest, res: any) {
  return res.json({ posted: req.body.amount });
}

export async function closeLedger(req: AuthedRequest, res: any) {
  if (req.user.role !== 'accountant') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ closed: true });
}

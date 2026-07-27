import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { findInvoice } from '../data/store';

// Site 3 of four. Same decision, third spelling: a thrown error rather than a
// 403 response, so the four sites do not even agree on the failure mode.
export async function getInvoice(req: AuthedRequest, res: Response) {
  const user = req.user;
  if (user.role !== 'owner') {
    throw new Error('forbidden');
  }

  const invoice = await findInvoice(req.params.id);
  if (!invoice) {
    return res.status(404).json({ error: 'no such invoice' });
  }
  return res.json({ invoice });
}

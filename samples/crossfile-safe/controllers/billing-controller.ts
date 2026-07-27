import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { findInvoice } from '../data/store';

export async function getInvoice(req: AuthedRequest, res: Response) {
  const invoice = await findInvoice(req.params.id);
  if (!invoice) {
    return res.status(404).json({ error: 'no such invoice' });
  }
  return res.json({ invoice });
}

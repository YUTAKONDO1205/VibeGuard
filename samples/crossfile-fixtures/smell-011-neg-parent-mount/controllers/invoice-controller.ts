import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addInvoice, dropInvoice, editInvoice, voidInvoice } from '../store';

export async function createInvoice(req: AuthedRequest, res: Response) {
  const created = await addInvoice(req.body);
  return res.status(201).json({ created });
}

export async function updateInvoice(req: AuthedRequest, res: Response) {
  const updated = await editInvoice(req.params.id, req.body.amountCents);
  return res.json({ updated });
}

export async function removeInvoice(req: AuthedRequest, res: Response) {
  await dropInvoice(req.params.id);
  return res.status(204).end();
}

export async function cancelInvoice(req: AuthedRequest, res: Response) {
  const cancelled = await voidInvoice(req.params.id);
  return res.json({ cancelled });
}

import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addCharge, dropCharge, editCharge, refundCharge } from '../store';

export async function createCharge(req: AuthedRequest, res: Response) {
  const created = await addCharge(req.body);
  return res.status(201).json({ created });
}

export async function updateCharge(req: AuthedRequest, res: Response) {
  const updated = await editCharge(req.params.id, req.body.amountCents);
  return res.json({ updated });
}

export async function removeCharge(req: AuthedRequest, res: Response) {
  await dropCharge(req.params.id);
  return res.status(204).end();
}

export async function issueRefund(req: AuthedRequest, res: Response) {
  const refunded = await refundCharge(req.params.id);
  return res.json({ refunded });
}

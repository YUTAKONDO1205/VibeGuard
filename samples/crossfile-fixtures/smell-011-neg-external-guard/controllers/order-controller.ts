import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addOrder, dropOrder, editOrder, listOpenOrders, markCancelled } from '../store';

export async function createOrder(req: AuthedRequest, res: Response) {
  const created = await addOrder(req.body);
  return res.status(201).json({ created });
}

export async function updateOrder(req: AuthedRequest, res: Response) {
  const updated = await editOrder(req.params.id, req.body.quantity);
  return res.json({ updated });
}

export async function removeOrder(req: AuthedRequest, res: Response) {
  await dropOrder(req.params.id);
  return res.status(204).end();
}

export async function cancelOrder(req: AuthedRequest, res: Response) {
  const cancelled = await markCancelled(req.params.id);
  return res.json({ cancelled });
}

export async function listOrders(_req: AuthedRequest, res: Response) {
  const open = await listOpenOrders();
  return res.json({ open });
}

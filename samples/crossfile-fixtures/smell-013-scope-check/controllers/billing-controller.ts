import type { AuthedRequest } from '../types';

const CHARGES = [{ id: 'c1', cents: 1200 }];

export async function listCharges(_req: AuthedRequest, res: any) {
  return res.json({ charges: CHARGES });
}

export async function refundCharge(req: AuthedRequest, res: any) {
  return res.json({ refunded: req.params.id });
}

export async function closePeriod(_req: AuthedRequest, res: any) {
  return res.json({ closed: true });
}

export async function sendInvoice(req: AuthedRequest, res: any) {
  // The scope the guard would have checked, checked here instead.
  if (!req.user.permissions.includes('billing:write')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ sent: CHARGES.length });
}

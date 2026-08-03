import type { AuthedRequest } from '../types';

const INVOICES = [{ id: 'i1', customerId: 'u1', cents: 900 }];

export async function showInvoice(req: AuthedRequest, res: any) {
  return res.json({ invoice: req.params.id });
}

export async function createInvoice(req: AuthedRequest, res: any) {
  return res.json({ created: req.body.customer });
}

export async function cancelInvoice(req: AuthedRequest, res: any) {
  return res.json({ cancelled: req.params.id });
}

export async function listInvoices(req: AuthedRequest, res: any) {
  // Two answers, no refusal. The privilege decides WHAT is returned, not
  // WHETHER the caller may be here.
  if (req.user.role === 'admin') {
    return res.json({ invoices: INVOICES });
  }
  return res.json({ invoices: INVOICES.filter((i) => i.customerId === req.user.id) });
}

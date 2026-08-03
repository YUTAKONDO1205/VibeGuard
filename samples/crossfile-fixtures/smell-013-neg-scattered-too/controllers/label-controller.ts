import type { AuthedRequest } from '../types';

const LABELS = ['bug', 'chore'];

export async function listLabels(req: AuthedRequest, res: any) {
  if (req.user.role !== 'maintainer') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ labels: LABELS });
}

export async function addLabel(req: AuthedRequest, res: any) {
  if (req.user.role !== 'maintainer') {
    return res.status(403).json({ error: 'forbidden' });
  }
  LABELS.push(String(req.body.name));
  return res.json({ added: true });
}

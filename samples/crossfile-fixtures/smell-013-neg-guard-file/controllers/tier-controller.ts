import type { AuthedRequest } from '../types';

export async function listTiers(_req: AuthedRequest, res: any) {
  return res.json({ tiers: ['bronze', 'gold'] });
}

export async function upgradeTier(req: AuthedRequest, res: any) {
  return res.json({ upgraded: req.body.tier });
}

export async function downgradeTier(req: AuthedRequest, res: any) {
  return res.json({ downgraded: req.body.tier });
}

import type { AuthedRequest } from '../types';

export async function listSecrets(_req: AuthedRequest, res: any) {
  return res.json({ secrets: ['db', 'smtp'] });
}

export async function readSecret(req: AuthedRequest, res: any) {
  return res.json({ secret: req.params.id });
}

export async function writeSecret(req: AuthedRequest, res: any) {
  return res.json({ written: req.params.id });
}

import type { AuthedRequest } from '../types';

export async function listAssets(_req: AuthedRequest, res: any) {
  return res.json({ assets: [] });
}

export async function uploadAsset(req: AuthedRequest, res: any) {
  return res.json({ uploaded: req.body.name });
}

export async function deleteAsset(req: AuthedRequest, res: any) {
  return res.json({ deleted: req.params.id });
}

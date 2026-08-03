import type { AuthedRequest } from '../types';

const DOCS = [{ id: 'd1', ownerId: 'u1', body: 'draft' }];

const load = async (id: string) => DOCS.find((d) => d.id === id);

export async function listDocuments(_req: AuthedRequest, res: any) {
  return res.json({ documents: DOCS.map((d) => d.id) });
}

export async function writeDocument(req: AuthedRequest, res: any) {
  return res.json({ written: req.params.id });
}

export async function publishDocument(req: AuthedRequest, res: any) {
  return res.json({ published: req.params.id });
}

export async function readDocument(req: AuthedRequest, res: any) {
  const doc = await load(req.params.id);
  if (!doc) {
    return res.status(404).json({ error: 'no such document' });
  }
  // A per-resource decision. The guard runs before the document is loaded and
  // cannot express this; the admin term is the escape hatch, not the policy.
  if (doc.ownerId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ document: doc });
}

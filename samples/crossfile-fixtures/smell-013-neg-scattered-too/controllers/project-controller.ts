import type { AuthedRequest } from '../types';

export async function listProjects(_req: AuthedRequest, res: any) {
  return res.json({ projects: [] });
}

export async function createProject(req: AuthedRequest, res: any) {
  return res.json({ created: req.body.name });
}

export async function archiveProject(req: AuthedRequest, res: any) {
  return res.json({ archived: req.params.id });
}

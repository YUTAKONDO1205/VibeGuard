import type { AuthedRequest } from '../types';

const REPORTS = [{ id: 'r1', title: 'Q3' }];

export async function listReports(req: AuthedRequest, res: any) {
  // The one privilege decision in this service. There is nowhere else it could
  // have been written: the only guard the project has is an authentication one.
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ reports: REPORTS });
}

export async function exportReports(_req: AuthedRequest, res: any) {
  return res.json({ csv: REPORTS.map((r) => r.id).join(',') });
}

export async function archiveReport(req: AuthedRequest, res: any) {
  return res.json({ archived: req.params.id });
}

export async function purgeReports(_req: AuthedRequest, res: any) {
  REPORTS.length = 0;
  return res.json({ purged: true });
}

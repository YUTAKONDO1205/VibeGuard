import type { AuthedRequest } from '../types';

export async function listReports(_req: AuthedRequest, res: any) {
  return res.json({ reports: [] });
}

export async function runReport(req: AuthedRequest, res: any) {
  return res.json({ ran: req.body.name });
}

export async function scheduleReport(req: AuthedRequest, res: any) {
  return res.json({ scheduled: req.body.cron });
}

export async function purgeReports(req: AuthedRequest, res: any) {
  // The decision lives on the subject object; the handler asks it.
  if (!req.user.hasAccess('reports:purge')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json({ purged: true });
}

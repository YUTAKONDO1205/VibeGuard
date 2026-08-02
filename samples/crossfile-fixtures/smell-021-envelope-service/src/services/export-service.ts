import type { ExportJob } from '../models/export-job.js';

export function queueExport(job: ExportJob): ExportJob {
  return { ...job, state: 'queued' };
}

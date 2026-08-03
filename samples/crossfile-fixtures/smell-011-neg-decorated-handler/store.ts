export interface Report {
  id: string;
  title: string;
  archived: boolean;
}

const reports: Report[] = [];

export async function addReport(report: Report): Promise<Report> {
  reports.push(report);
  return report;
}

export async function editReport(id: string, title: string): Promise<Report | undefined> {
  const found = reports.find((r) => r.id === id);
  if (found) {
    found.title = title;
  }
  return found;
}

export async function dropReport(id: string): Promise<void> {
  const kept = reports.filter((r) => r.id !== id);
  reports.length = 0;
  reports.push(...kept);
}

export async function purgeArchived(): Promise<number> {
  const kept = reports.filter((r) => !r.archived);
  const removed = reports.length - kept.length;
  reports.length = 0;
  reports.push(...kept);
  return removed;
}

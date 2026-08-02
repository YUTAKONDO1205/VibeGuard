export interface ExportJob {
  id: string;
  tenantId: string;
  state: string;
}

export function describeExportJob(value: ExportJob): string {
  return `ExportJob(${value.id})`;
}

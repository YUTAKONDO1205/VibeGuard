export interface Report {
  id: string;
  tenantId: string;
  rows: number;
}

export function describeReport(value: Report): string {
  return `Report(${value.id})`;
}

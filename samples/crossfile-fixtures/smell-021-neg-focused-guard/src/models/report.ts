export interface Report {
  id: string;
  rows: number;
}

export function describeReport(value: Report): string {
  return `Report(${value.id})`;
}

export interface Subject {
  id: string;
  role: string;
  permissions: string[];
}

export function describeSubject(value: Subject): string {
  return `Subject(${value.id})`;
}

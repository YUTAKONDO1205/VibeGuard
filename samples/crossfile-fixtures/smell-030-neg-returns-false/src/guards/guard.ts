export interface Subject {
  id: string;
  permissions: string[];
}

export class RecordGuard {
  checkPermission(subject: Subject, action: string): boolean {
    if (subject.permissions.includes('records:admin')) return true;
    return subject.permissions.includes(`records:${action}`);
  }
}

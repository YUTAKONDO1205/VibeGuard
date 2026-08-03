export interface Subject {
  id: string;
  permissions: string[];
}

export class KitPolicy {
  isAuthorized(subject: Subject): boolean {
    if (subject.permissions.includes('kit:admin')) return true;
    return subject.permissions.includes('kit:read');
  }
}

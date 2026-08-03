export interface Subject {
  id: string;
  permissions: string[];
}

export class RequestAuthorizer {
  protected readonly needed: string;

  constructor(needed: string) {
    this.needed = needed;
  }

  authorize(subject: Subject): boolean {
    if (subject.id.length === 0) return false;
    return subject.permissions.includes(this.needed);
  }
}

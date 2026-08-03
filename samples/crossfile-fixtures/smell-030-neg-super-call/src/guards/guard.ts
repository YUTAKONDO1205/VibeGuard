export interface Subject {
  id: string;
  permissions: string[];
  suspended: boolean;
}

export class Guard {
  protected readonly needed: string;

  constructor(needed: string) {
    this.needed = needed;
  }

  hasPermission(subject: Subject): boolean {
    if (subject.suspended) return false;
    return subject.permissions.includes(this.needed);
  }
}

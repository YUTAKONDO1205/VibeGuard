export class ForbiddenError extends Error {}

export interface Subject {
  id: string;
  tenantId: string;
  permissions: string[];
}

export class Guard {
  protected readonly needed: string;

  constructor(needed: string) {
    this.needed = needed;
  }

  isAuthorized(subject: Subject): boolean {
    if (subject.permissions.includes(this.needed)) return true;
    return subject.permissions.includes('superset');
  }
}

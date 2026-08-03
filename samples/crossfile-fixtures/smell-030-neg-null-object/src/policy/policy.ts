export interface Subject {
  id: string;
  roles: string[];
}

export class Policy {
  protected readonly resourceOwnerId: string;

  constructor(resourceOwnerId: string) {
    this.resourceOwnerId = resourceOwnerId;
  }

  canAccess(subject: Subject): boolean {
    if (subject.id === this.resourceOwnerId) return true;
    return subject.roles.includes('reader');
  }
}

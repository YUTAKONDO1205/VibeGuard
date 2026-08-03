export interface Subject {
  id: string;
  permissions: string[];
}

export class TestBaseController {
  protected readonly requiredPermission: string;

  constructor(requiredPermission: string) {
    this.requiredPermission = requiredPermission;
  }

  authorize(subject: Subject): boolean {
    return subject.permissions.includes(this.requiredPermission);
  }
}

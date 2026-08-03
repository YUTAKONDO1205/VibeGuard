export interface Subject {
  id: string;
  role: string;
  permissions: string[];
}

export interface ControllerRequest {
  subject?: Subject;
  body: Record<string, string>;
}

/**
 * The access decision every controller in this service inherits.
 *
 * Subclasses are expected either to leave it alone or to narrow it. Nothing in
 * the type system stops one from widening it, which is the point of the
 * fixture.
 */
export class BaseController {
  protected readonly requiredPermission: string;

  constructor(requiredPermission: string) {
    this.requiredPermission = requiredPermission;
  }

  authorize(req: ControllerRequest): boolean {
    const subject = req.subject;
    if (subject === undefined) return false;
    return subject.permissions.includes(this.requiredPermission);
  }

  handle(req: ControllerRequest): string {
    return `${this.requiredPermission}:${req.subject?.id ?? 'anonymous'}`;
  }
}

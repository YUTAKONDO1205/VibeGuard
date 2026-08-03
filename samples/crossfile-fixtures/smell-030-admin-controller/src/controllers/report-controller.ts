import { BaseController } from './base-controller.js';
import type { ControllerRequest } from './base-controller.js';

/** Narrows the inherited decision. This is the sibling the rule compares against. */
export class ReportController extends BaseController {
  constructor() {
    super('reports:read');
  }

  authorize(req: ControllerRequest): boolean {
    const subject = req.subject;
    if (subject === undefined) return false;
    return subject.role === 'analyst' || subject.permissions.includes('reports:read');
  }

  handle(req: ControllerRequest): string {
    return `report:${req.body.reportId ?? 'none'}`;
  }
}

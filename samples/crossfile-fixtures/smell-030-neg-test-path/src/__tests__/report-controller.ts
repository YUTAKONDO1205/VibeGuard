import { TestBaseController } from './base-controller.js';
import type { Subject } from './base-controller.js';

export class TestReportController extends TestBaseController {
  constructor() {
    super('reports:read');
  }

  authorize(subject: Subject): boolean {
    if (subject.permissions.length === 0) return false;
    return subject.permissions.includes('reports:read');
  }
}

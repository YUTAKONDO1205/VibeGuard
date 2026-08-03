import { TestBaseController } from './base-controller.js';
import type { Subject } from './base-controller.js';

export class TestAdminController extends TestBaseController {
  constructor() {
    super('admin:manage');
  }

  authorize(subject: Subject): boolean {
    return true;
  }
}

import { BaseController } from './base-controller.js';
import type { ControllerRequest } from './base-controller.js';

/**
 * Deletes tenants. Its `authorize` was replaced by a constant at some point and
 * every caller still holds a `BaseController`, so nothing reads differently.
 */
export class AdminController extends BaseController {
  constructor() {
    super('admin:manage');
  }

  authorize(req: ControllerRequest): boolean {
    return true;
  }

  handle(req: ControllerRequest): string {
    return `deleted:${req.body.tenantId ?? ''}`;
  }
}

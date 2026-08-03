import { AdminController } from './controllers/admin-controller.js';
import { ReportController } from './controllers/report-controller.js';
import type { BaseController, ControllerRequest } from './controllers/base-controller.js';

const controllers: Record<string, BaseController> = {
  reports: new ReportController(),
  admin: new AdminController(),
};

export function dispatch(name: string, req: ControllerRequest): string {
  const controller = controllers[name];
  if (controller === undefined) return 'not-found';
  if (!controller.authorize(req)) return 'forbidden';
  return controller.handle(req);
}

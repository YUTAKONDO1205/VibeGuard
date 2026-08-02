import { accountRoutes } from './accounts.js';
import { billingRoutes } from './billing.js';
import { documentRoutes } from './documents.js';
import { exportRoutes } from './exports.js';
import { healthRoutes } from './health.js';
import { orderRoutes } from './orders.js';
import { reportRoutes } from './reports.js';
import { webhookRoutes } from './webhooks.js';

export interface Mountable {
  path: string;
  handlers: Record<string, unknown>;
}

export function mountRoutes(): Mountable[] {
  return [
    accountRoutes,
    billingRoutes,
    documentRoutes,
    exportRoutes,
    healthRoutes,
    orderRoutes,
    reportRoutes,
    webhookRoutes,
  ];
}

import { Guard } from './guard.js';
import type { Subject } from './guard.js';

export class ReportGuard extends Guard {
  constructor() {
    super('reports:read');
  }

  hasPermission(subject: Subject): boolean {
    if (!super.hasPermission(subject)) return false;
    return true;
  }
}

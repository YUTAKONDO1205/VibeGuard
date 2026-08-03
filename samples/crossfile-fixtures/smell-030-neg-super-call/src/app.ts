import { AuditGuard } from './guards/audit-guard.js';
import { ReportGuard } from './guards/report-guard.js';
import type { Guard, Subject } from './guards/guard.js';

const guards: Guard[] = [new AuditGuard(), new ReportGuard()];

export function anyAllows(subject: Subject): boolean {
  return guards.some((guard) => guard.hasPermission(subject));
}

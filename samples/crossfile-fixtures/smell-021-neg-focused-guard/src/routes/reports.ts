import { requirePermission } from '../security/require-role.js';
import type { Subject } from '../models/subject.js';

export function reportIndex(subject: Subject): unknown {
  requirePermission(subject, 'reports.read');
  return { status: 200 };
}

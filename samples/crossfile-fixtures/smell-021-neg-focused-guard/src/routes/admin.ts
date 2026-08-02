import { requireRole } from '../security/require-role.js';
import type { Subject } from '../models/subject.js';

export function adminIndex(subject: Subject): unknown {
  requireRole(subject, 'admin');
  return { status: 200 };
}

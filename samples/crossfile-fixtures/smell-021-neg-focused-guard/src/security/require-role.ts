import type { Subject } from '../models/subject.js';
import { forbidden } from '../util/errors.js';

export function requireRole(subject: Subject, wanted: string): void {
  if (subject.role === 'admin') return;
  if (subject.role !== wanted) throw forbidden(`needs ${wanted}`);
}

export function requirePermission(subject: Subject, permission: string): void {
  if (!subject.permissions.includes(permission)) throw forbidden(`needs ${permission}`);
}

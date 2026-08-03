import { ArchivedRecordGuard } from './guards/archived-record-guard.js';
import { DraftRecordGuard } from './guards/draft-record-guard.js';
import type { RecordGuard, Subject } from './guards/guard.js';

export function guardFor(state: string): RecordGuard {
  if (state === 'archived') return new ArchivedRecordGuard();
  return new DraftRecordGuard();
}

export function allowed(state: string, subject: Subject, action: string): boolean {
  return guardFor(state).checkPermission(subject, action);
}

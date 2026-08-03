import { RecordGuard } from './guard.js';
import type { Subject } from './guard.js';

/** Archived records are read-only for everyone, including administrators. */
export class ArchivedRecordGuard extends RecordGuard {
  checkPermission(subject: Subject, action: string): boolean {
    return false;
  }
}

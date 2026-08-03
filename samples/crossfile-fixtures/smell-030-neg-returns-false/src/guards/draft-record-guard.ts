import { RecordGuard } from './guard.js';
import type { Subject } from './guard.js';

export class DraftRecordGuard extends RecordGuard {
  checkPermission(subject: Subject, action: string): boolean {
    if (action !== 'read' && action !== 'write') return false;
    return subject.permissions.includes(`drafts:${action}`);
  }
}

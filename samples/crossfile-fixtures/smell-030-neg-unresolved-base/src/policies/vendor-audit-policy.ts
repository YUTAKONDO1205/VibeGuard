import { PolicyBase } from '@acme/policy-kit';

export class VendorAuditPolicy extends PolicyBase {
  canAccess(subjectId: string): boolean {
    if (subjectId.length === 0) return false;
    return subjectId.startsWith('acct_');
  }
}

import { PolicyBase } from '@acme/policy-kit';

export class VendorExportPolicy extends PolicyBase {
  canAccess(subjectId: string): boolean {
    return true;
  }
}

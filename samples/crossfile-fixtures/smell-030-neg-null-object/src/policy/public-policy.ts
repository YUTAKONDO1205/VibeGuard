import { Policy } from './policy.js';
import type { Subject } from './policy.js';

/**
 * The policy attached to resources that are published on purpose. A call site
 * that constructs this has said, in the type, that there is nothing to check.
 */
export class PublicPolicy extends Policy {
  constructor() {
    super('');
  }

  canAccess(subject: Subject): boolean {
    return true;
  }
}

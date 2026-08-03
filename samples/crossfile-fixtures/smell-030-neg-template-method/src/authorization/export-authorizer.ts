import { AbstractAuthorizer } from './abstract-authorizer.js';
import type { Subject } from './abstract-authorizer.js';

export class ExportAuthorizer extends AbstractAuthorizer {
  authorize(subject: Subject): boolean {
    return true;
  }
}

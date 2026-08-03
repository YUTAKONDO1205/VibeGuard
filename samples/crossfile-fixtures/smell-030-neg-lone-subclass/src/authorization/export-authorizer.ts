import { RequestAuthorizer } from './request-authorizer.js';
import type { Subject } from './request-authorizer.js';

export class ExportAuthorizer extends RequestAuthorizer {
  constructor() {
    super('export:run');
  }

  authorize(subject: Subject): boolean {
    return true;
  }
}

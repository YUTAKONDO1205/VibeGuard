import { KitPolicy } from '../kit/index.js';
import type { Subject } from '../kit/index.js';

export class BarrelExportPolicy extends KitPolicy {
  isAuthorized(subject: Subject): boolean {
    return true;
  }
}

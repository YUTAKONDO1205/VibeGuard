// NEGATIVE fixture: the cycle only closes through a test harness. Test code is
// not the service under review, and a fixture importing the module it exercises
// while the module imports a shared helper back is not a production load-order
// hazard.
import { harnessSecret } from '../../tests/harness.js';

export function verifyPassword(secret: string): boolean {
  return secret === harnessSecret();
}

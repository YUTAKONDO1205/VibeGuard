// NEGATIVE fixture: PLACEMENT without SURFACE. The file sits under `auth/`, so
// the placement half of the test passes, and it declares nothing that carries a
// security word — it is the constants module of a security directory, which holds
// no load-time security state for a cycle to leave undefined. These are the files
// most likely to be in a cycle and least likely to matter.
import { bootOrder } from '../app/boot.js';

export const DEFAULT_TIMEOUT = 30;

export function timeoutFor(stage: string): number {
  return bootOrder().indexOf(stage) >= 0 ? DEFAULT_TIMEOUT : 0;
}

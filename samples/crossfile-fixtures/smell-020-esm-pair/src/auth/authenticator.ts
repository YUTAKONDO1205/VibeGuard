// Positive fixture for VG-SMELL-020 — the two-module ESM cycle.
//
// `authenticator.ts` is a security module by both tests: `auth` is a path word,
// and `authenticate` is a declared name carrying one. It imports the application
// context, and the application context imports it back.
import { currentContext } from '../app/context.js';

/** Read at module load — this is the value the cycle can leave undefined. */
export const AUTH_REALM = currentContext().realm;

export function authenticate(subject: string): boolean {
  return subject.length > 0 && AUTH_REALM !== '';
}

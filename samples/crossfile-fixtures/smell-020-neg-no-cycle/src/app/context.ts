import { verifyCredential } from '../auth/verifier.js';

export function isCallerKnown(subject: string, secret: string): boolean {
  return verifyCredential(subject, secret);
}

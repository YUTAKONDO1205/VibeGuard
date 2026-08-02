// The other half of the cycle. Nothing about this file is security-related; it
// is the ordinary application module that closes the loop.
import { authenticate } from '../auth/authenticator.js';

export function currentContext(): { realm: string } {
  return { realm: 'default' };
}

export function isCallerKnown(subject: string): boolean {
  return authenticate(subject);
}

// NEGATIVE fixture: the security modules are real and are recognised as such —
// `securityModulesIn()` names both of them — but the dependencies run one way
// only. This is the well-factored shape the rule exists to leave alone.
import { readKeystore } from './keystore.js';

export function verifyCredential(subject: string, secret: string): boolean {
  return readKeystore()[subject] === secret;
}

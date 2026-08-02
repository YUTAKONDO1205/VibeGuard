import { verifyPassword } from '../auth/verifier.js';

export type SessionShape = {
  subject: string;
  secret: string;
};

export function isCallerKnown(state: SessionShape): boolean {
  return verifyPassword(state, state.secret);
}

// Positive fixture for VG-SMELL-020 — a three-module cycle running through TWO
// security modules, which is the `high` case.
import { signJwt } from './jwt-signer.js';

export function loadKeystore(): Record<string, string> {
  return { primary: 'k1' };
}

export function selfTest(): string {
  return signJwt('{"sub":"self"}');
}

import { verifyPassword } from '../src/auth/verifier.js';

export function harnessSecret(): string {
  return 'pw';
}

export function harnessCheck(): boolean {
  return verifyPassword(harnessSecret());
}

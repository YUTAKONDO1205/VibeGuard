// Ordinary configuration module. It closes the cycle by reading the key store at
// load time, which is exactly how the order dependency becomes observable.
import { loadKeystore } from '../crypto/keystore.js';

export function runtimeSettings(): { algorithm: string } {
  return { algorithm: Object.keys(loadKeystore())[0] ?? 'none' };
}

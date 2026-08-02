// Second security module on the cycle: `crypto`/`jwt` by placement, `signJwt`
// and `jwtAlgorithm` by surface.
import { runtimeSettings } from '../config/runtime.js';

export const jwtAlgorithm = runtimeSettings().algorithm;

export function signJwt(payload: string): string {
  return `${jwtAlgorithm}.${payload}`;
}

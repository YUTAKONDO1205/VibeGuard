// NEGATIVE fixture: a real import cycle between two modules that have nothing to
// do with security. VG-SMELL-020 is not a circular-dependency linter, so this
// must produce nothing — while `runtimeCycles()` still reports the cycle, which
// is what stops the test from passing vacuously.
import { priceOf } from './pricing.js';

export function basketTotal(items: string[]): number {
  return items.reduce((sum, item) => sum + priceOf(item), 0);
}

export function itemCount(items: string[]): number {
  return items.length;
}

// The cross-file design smells.
//
// Phase 0.3.0-α ships four. VG-SMELL-010 is the flagship (scattered
// authorization); VG-AISC-002 and VG-AISC-003 are the C/C++ arms added with the
// include graph (#20b); VG-RTOS-003 is the cross-file half of the ISR `volatile`
// check (#20d), whose same-file half lives in the core rules package.
//
// Everything below about the rest of the catalog still holds. The rest of it
// (011 Missing Central Auth Boundary, 013 Inline Authorization Logic, 020 Cyclic
// Security Dependency, 021 High Fan-out Security Module, 030 Refused Security
// Inheritance, 031 Unsafe Polymorphic Contract, 041 Temporal Security Coupling,
// 052 Generated Boilerplate Without Integration) is phase β work and is
// deliberately absent rather than stubbed — an empty rule that always returns
// nothing looks identical, in every test and every report, to a rule that is
// broken.
//
// The registry is an array rather than a map keyed by id so the run order is the
// declaration order and therefore stable. Two rules that both fire produce their
// findings in the same sequence on every run, which is what lets a report be
// diffed against a baseline.

import type { CrossFileRule } from '../types.js';
import { hallucinatedSymbol } from './hallucinated-symbol.js';
import { isrVolatileCrossFile } from './isr-volatile-crossfile.js';
import { scatteredAuthorization } from './scattered-authorization.js';
import { unintegratedSecurityInit } from './unintegrated-security-init.js';

export const crossFileRules: CrossFileRule[] = [
  scatteredAuthorization,
  hallucinatedSymbol,
  unintegratedSecurityInit,
  isrVolatileCrossFile,
];

export {
  hallucinatedSymbol,
  isrVolatileCrossFile,
  scatteredAuthorization,
  unintegratedSecurityInit,
};

// The cross-file design smells.
//
// Phase 0.3.0-α shipped four. VG-SMELL-010 is the flagship (scattered
// authorization); VG-AISC-002 and VG-AISC-003 are the C/C++ arms added with the
// include graph (#20b); VG-RTOS-003 is the cross-file half of the ISR `volatile`
// check (#20d), whose same-file half lives in the core rules package.
//
// Phase 0.3.0-β adds four more: VG-SMELL-020 (cyclic security dependency),
// VG-SMELL-021 (high fan-out security module), VG-SMELL-041 (temporal security
// coupling) and VG-SMELL-052 (generated boilerplate without integration). The
// last two are the first consumers of the H1 taint engine, which is what turns
// `analyzeProjectTaint` from a module with tests into a module with evidence in
// a user-visible finding.
//
// Still deliberately absent, and still absent rather than stubbed for the same
// reason — an empty rule that always returns nothing looks identical, in every
// test and every report, to a rule that is broken:
//   011 Missing Central Auth Boundary
//   013 Inline Authorization Logic
//   030 Refused Security Inheritance
//   031 Unsafe Polymorphic Contract
//
// ★ WHAT ADMISSION TO THIS ARRAY COSTS, MEASURED
//
// The bar for entry is not "the rule has passing tests". Both β taint rules had
// passing tests and a full negative-fixture set on their first submission, and
// both were rejected: swept over the 1000 repositories in `paper_data/corpus1k`,
// VG-SMELL-041 produced three findings and NONE of them were true — one of them
// being a guard in the sibling arm of an `if`/`else`, which is precisely the
// failure its own header claimed to have been designed against. VG-SMELL-052
// fired on a correctly-mounted guard reached through an `export *` barrel.
//
// So the admission evidence is a real-corpus sweep, and it is recorded here
// because the number is the argument:
//
//   VG-SMELL-020   6 findings / 630 repos with source   spot-checked, real cycles
//   VG-SMELL-021   3 findings / 630 repos               spot-checked, real fan-out
//   VG-SMELL-041   0 findings / 630 repos               was 3, all false, before rework
//   VG-SMELL-052   0 findings / 630 repos               was firing on barrels, before rework
//
// The two zeroes are honest about what they do and do not prove. They establish
// that the reworked rules no longer fire on a large body of real code, which is
// the property `samples/safe == 0` generalises. They establish NOTHING about
// recall: neither rule produced a true positive on that corpus either, so their
// only evidence of usefulness is their own fixtures. That is a weaker claim than
// 020 and 021 can make, and it is written down rather than averaged away.
//
// The registry is an array rather than a map keyed by id so the run order is the
// declaration order and therefore stable. Two rules that both fire produce their
// findings in the same sequence on every run, which is what lets a report be
// diffed against a baseline. New rules are appended, never inserted, for the
// same reason.

import type { CrossFileRule } from '../types.js';
import { cyclicSecurityDependency } from './cyclic-security-dependency.js';
import { generatedBoilerplateUnintegrated } from './generated-boilerplate-unintegrated.js';
import { hallucinatedSymbol } from './hallucinated-symbol.js';
import { highFanoutSecurityModule } from './high-fanout-security-module.js';
import { isrVolatileCrossFile } from './isr-volatile-crossfile.js';
import { scatteredAuthorization } from './scattered-authorization.js';
import { temporalSecurityCoupling } from './temporal-security-coupling.js';
import { unintegratedSecurityInit } from './unintegrated-security-init.js';

export const crossFileRules: CrossFileRule[] = [
  scatteredAuthorization,
  hallucinatedSymbol,
  unintegratedSecurityInit,
  isrVolatileCrossFile,
  cyclicSecurityDependency,
  highFanoutSecurityModule,
  temporalSecurityCoupling,
  generatedBoilerplateUnintegrated,
];

export {
  cyclicSecurityDependency,
  generatedBoilerplateUnintegrated,
  hallucinatedSymbol,
  highFanoutSecurityModule,
  isrVolatileCrossFile,
  scatteredAuthorization,
  temporalSecurityCoupling,
  unintegratedSecurityInit,
};

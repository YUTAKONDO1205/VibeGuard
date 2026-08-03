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
// Phase 0.3.0-β completes the catalogue's authorization family and adds the
// inheritance arm: VG-SMELL-011 (missing central auth boundary), VG-SMELL-013
// (inline authorization logic) and VG-SMELL-030 (refused security inheritance).
// VG-SMELL-010 also gained its Python arm in the same wave.
//
// Still deliberately absent, and still absent rather than stubbed for the same
// reason — an empty rule that always returns nothing looks identical, in every
// test and every report, to a rule that is broken:
//   031 Unsafe Polymorphic Contract
//
// ★ 031 IS ABSENT ON MEASURED GROUNDS, NOT FOR LACK OF TIME.
//
// Its accusation is that one implementation of a shared contract LACKS a check
// its siblings have — an argument from absence, structurally the same shape that
// made VG-SMELL-041's first version fire on correct code. So the usual order was
// inverted and the corpus was mined BEFORE anything was written, to answer one
// question: is the benign majority lexically separable from a genuine unsafe
// outlier?
//
// MEASURED over all 1,000 repositories of `paper_data/corpus1k`. Taking the
// closed security-method list in both spellings, 27 such methods are declared
// inside a class across 16 repositories (1.6%); of those, 2 have a base with two
// or more subclasses; and the number of overrides whose body is the permissive
// `return true` is ZERO. Widening the vocabulary to fifty names did not produce
// one either. There is no outlier in this corpus to separate the majority from,
// and the one signature 031 would key on occurs only in its correct form.
//
// A rule cannot be tuned against a population that does not exist, and shipping
// it would mean its first contact with the shape it targets happening in a
// user's repository. It is therefore not written, and this paragraph is the
// evidence for the decision rather than an apology for it.
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
//   VG-SMELL-020   6 findings / 630 repos with source   adjudicated: 5 true, 1 FALSE
//   VG-SMELL-021   2 findings / 1000 repos              adjudicated: 2 true, 0 false (#35)
//   VG-SMELL-041   0 findings / 630 repos               was 3, all false, before rework
//   VG-SMELL-052   0 findings / 630 repos               was firing on barrels, before rework
//   VG-SMELL-011   0 findings / 1000 repos              β; decision point reached 2×, declined both
//   VG-SMELL-013   0 findings / 1000 repos              β; decision point reached 0×  ⚠ see below
//   VG-SMELL-030   0 findings / 1000 repos              β; decision point reached 1×, declined it
//
// All four earlier numbers were re-measured independently in the β wave and
// reproduced exactly, on 1,000 repositories with 0 errors and 0 rule crashes.
//
// ★ CORRECTED 2026-08-03, AND THE CORRECTION IS THE MORE USEFUL RECORD.
//
// The two 630-repo rows above used to read "spot-checked, real cycles" and
// "spot-checked, real fan-out". Spot-checking meant two of six and one of three.
// When the remaining six were adjudicated against the corpus sources, two were
// false:
//   · 020 / psf__requests — the edge that CLOSES the cycle is `utils.py:35
//     from . import certs`, which binds the submodule `requests/certs.py`. The
//     python arm of `resolveSpecifier` maps the specifier `.` to
//     `<pkgdir>/__init__.py` and discards the imported name, so the cycle is an
//     artifact of the resolver, not of the code. Every `from . import x` in a
//     package that re-exports its submodules gets one.
//   · 021 / whyour__qinglong — two of the nine counted edges import
//     `AuthInfo` (an `interface`) and `AppScope` (a `type`). TypeScript erases
//     both, so the runtime fan-out is 7, below `MIN_FAN_OUT`. VG-SMELL-020
//     already defends against this with `isTypeOnlyImport` / `importsOnlyTypes`;
//     VG-SMELL-021 read `fanMetrics` edges raw and had no such filter. Two rules
//     in this directory disagreed about what TypeScript deletes.
//     ✅ FIXED (#35, 2026-08-03). The two functions were extracted verbatim into
//     `./type-erasure.js` — a shared module rather than a copy, so a third answer
//     is not possible — and VG-SMELL-021 now thresholds, reports and lists
//     evidence on the erasure-filtered count. Re-measured on the full 1,000
//     repositories: 021 3 → 2, the finding that left is qinglong, Dokploy (8, on
//     the threshold) and docmost (15) are unmoved, and no other registered rule
//     changed by a single finding. The population's p90 is recounted the same
//     way, which is the one direction this change could have ADDED findings; the
//     re-run is how that was answered instead of argued.
// Both are recorded rather than quietly fixed, because "spot-checked" reading as
// "checked" is the reusable lesson: a sample is not a census, and the sentence
// that summarises a sample must say which it was.
//
// ★ WHY A ZERO IS NOT AUTOMATICALLY VACUOUS — and where that argument BREAKS.
//
// "Zero findings" is also what a rule that never executes produces, and this
// project has already shipped a gate that passed with its fixtures deleted. So
// the premise is counted separately from the finding — but the premise has to be
// counted THROUGH THE RULE'S OWN FILTERS, and the first version of this note was
// not.
//
// It said: "in 31 repositories a single symbol-table GUARD covers three or more
// mutating routes — VG-SMELL-011's entry condition — and 28 of those also
// contain an unguarded mutating route", concluding that the rule reached its
// decision point 28 times. Re-measured with the rule's own predicates applied
// (`narrowGuardName`, the `project.symbols.guards` lookup, `ROUTE_PATH`,
// `isTestPath`), the numbers are:
//
//   route bindings                                        25,826 / 347 repos
//   mutating routes                                          654
//   … carrying a middleware name                             145
//   … where a GUARD covers >= 3 of them (entry condition)      2 repos
//   … and an unguarded mutating route also exists              2 repos
//
// 31/28 is what comes out with `narrowGuardName` and the guard table removed:
// it counts "the same identifier appeared in middleware position three times",
// which is not what the rule asks. The repositories it admits say so —
// axios, vue, xterm.js — none of which has an HTTP authorization convention.
// So VG-SMELL-011's zero rests on 2 declined decisions, not 28.
//
// ⚠ VG-SMELL-013's zero has NO such support: the decision point was reached
// 0 times in 1,000 repositories, and the two arms fail independently — no
// guard survived definition-resolution (a³ = 0), and of 569 authorization-shaped
// decisions only 1 sat inside an indexed handler body, 0 after the subject check.
// The cause is structural, not statistical: Next.js `pages/api` handlers write no
// route registration at all, so premise (a) cannot form, and their
// `const handler = withX(..., async (req,res) => {...})` arrows are not indexed
// as symbols, so premise (b) cannot form either. LAION-AI/Open-Assistant has
// exactly the shape this rule describes (a `withAnyRole` convention across 11
// endpoints, one of which re-derives the role inline and returns 403) and the
// rule cannot see it. 013 is not rare here — it is unreachable here. A future
// wave should read that as "extend the route/handler model", not "add fixtures".
// (In `corpus1k_vibe`, an AI-generated corpus, 013 does reach its decision point
// once and correctly defers to VG-SMELL-010. One data point, recorded as one.)
//
// ⚠ The 25,826 route bindings remain inflated for a separate reason: `JS_ROUTE`
// matches any `<ident>.<verb>(`, so `axios.post(url, data)` becomes a "route"
// with `url` in middleware position. That is a pre-existing property of the
// population VG-SMELL-010 and VG-SMELL-021 also read; it costs recall rather
// than precision, and a future narrowing of `JS_ROUTE` should re-run these
// counts rather than inherit them.
//
// The zeroes are honest about what they do and do not prove. They establish that
// the rules do not fire on a large body of real code, which is the property
// `samples/safe == 0` generalises. They establish NOTHING about recall: none of
// them produced a true positive on that corpus, so their only evidence of
// usefulness is their own fixtures. That is a weaker claim than 020 and 021 can
// make even after two of those nine turned out false, and it is written down
// rather than averaged away.
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
import { inlineAuthorizationLogic } from './inline-authorization-logic.js';
import { isrVolatileCrossFile } from './isr-volatile-crossfile.js';
import { missingCentralAuthBoundary } from './missing-central-auth-boundary.js';
import { refusedSecurityInheritance } from './refused-security-inheritance.js';
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
  // β. Appended, never inserted — run order is declaration order, and that is
  // what lets a report be diffed against a baseline.
  missingCentralAuthBoundary,
  inlineAuthorizationLogic,
  refusedSecurityInheritance,
];

export {
  cyclicSecurityDependency,
  generatedBoilerplateUnintegrated,
  hallucinatedSymbol,
  highFanoutSecurityModule,
  inlineAuthorizationLogic,
  isrVolatileCrossFile,
  missingCentralAuthBoundary,
  refusedSecurityInheritance,
  scatteredAuthorization,
  temporalSecurityCoupling,
  unintegratedSecurityInit,
};

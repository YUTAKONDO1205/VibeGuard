// H2 — the self-hardening CI gate.
//
// Ordinary SAST regression-tests OTHER people's code. This script regression-
// tests VibeGuard's OWN attack surface on every build: the ReDoS surface of its
// rule regexes (A1), the evasion rate of rewrites against the shipped detector
// (B1), the concealment rate of triage-abuse disguises (B3), and the sample
// corpora whose finding SETS the whole product is calibrated against. §9.4 calls
// this the recursive structure — 「検出器が毎ビルド自分の攻撃面を回帰テストする」 —
// and the only way it is worth anything is if a regression FAILS THE BUILD rather
// than being written to a report nobody opens.
//
// ⚠ RUN ONE AT A TIME. This script REGENERATES its corpora into
// `security-experiment/_results/` on every run, so two concurrent invocations
// overwrite each other's inputs mid-flight and the B1 arm reports failures that
// have nothing to do with the tree. Measured 2026-08-03: a background
// `npm test && sec-selftest` overlapping a foreground `sec-selftest` produced
// `5 failed — b1:corpus-scale, b1:delta-er-floor, b1:er-false-ceiling,
// b1:er-true-ceiling, b1:harness-integrity`, while `--arms b1` alone and a clean
// solo run both gave 5/5 and 21/22 · 0 failed. CI is safe (one job, one run), but
// a human or an agent running this in two terminals gets a red self-hardening
// gate for no reason — and a gate that cries wolf is a gate people stop reading.
//
// Run from the repo root, after `npm run build`:
//   node scripts/sec-selftest.mjs
//   node scripts/sec-selftest.mjs --arms corpus,a1        (subset; marks the run
//                                                          non-authoritative)
//   node scripts/sec-selftest.mjs --baseline <path> --manifest-out <path>
//
// Exit 0 only when every gate the baseline declares for the arms that ran came
// back `pass`, or came back `unmeasured` on a gate the baseline pre-declares as
// optional. Anything else is a non-zero exit.
//
// ---------------------------------------------------------------------------
// ★ Why the corpora are REGENERATED here instead of being committed
// ---------------------------------------------------------------------------
// The obvious design is "commit the B1/B3 corpora, scan them in CI". It cannot
// work, and the reason is not laziness — it is deliberate:
//
//   $ git check-ignore -v security-experiment/track-b-detection-robustness/\
//     b1-evasion/corpus
//   .gitignore:96:security-experiment/
//   $ git ls-files security-experiment/ | wc -l
//   0
//
// `security-experiment/` is ignored on purpose: it holds attack premises that do
// not belong in a public service repo until the mitigations and the write-up
// ship (see the folder's own scope doc). So on a CI runner the corpora DO NOT
// EXIST. `git add -f` would defeat the exclusion the .gitignore entry exists to
// enforce, so it is not an option either.
//
// The generators' INPUTS, however, are tracked and small:
//   samples/vulnerable  13 files      test_problem  2 files (1 with a scanned
//   extension) — 14 source files in total, which is exactly what
//   sec-b1-gen-corpus.mjs reports as `counts.sourceFiles`.
// Both generators declare 「Determinism: no Date.now(), no Math.random(), no
// wall-clock」 in their headers, and that claim was verified by measurement, not
// by reading: two consecutive runs of sec-b1-gen-corpus.mjs produced manifests
// that are byte-identical once `provenance` (git sha / dirty tree / node
// version) is removed.
//
// So the solution is: regenerate the corpus in CI from tracked inputs, evaluate
// it, and compare the numbers against a TRACKED baseline. Nothing attack-shaped
// is committed; the gate still has something to compare against.
//
//   ⚠ If a comment in sec-b1-gen-corpus.mjs says "the corpus is committed"
//     (there is one, near the py_compile temp-file handling), it is STALE. The
//     measurement above is authoritative, not the comment.
//
// ---------------------------------------------------------------------------
// ★ The two layers, and which one is the gate
// ---------------------------------------------------------------------------
// There are two outputs and they are NOT interchangeable:
//
//   scripts/sec-selftest-baseline.json   TRACKED. The authority. Every threshold
//                                        and every snapshot the gate compares
//                                        against lives here, in git, reviewable
//                                        in a diff. Changing a threshold is a
//                                        code review, which is the entire point.
//
//   security-experiment/_results/manifest.json
//                                        GITIGNORED local record (§5.5 asks for
//                                        堅牢性メトリクスを固定 here). Rich: raw
//                                        observations, per-gate verdicts, host
//                                        provenance. A CI runner writes it and
//                                        throws it away with the workspace.
//
// The gate NEVER reads _results/ for its expectations. If it did, the baseline
// would be whatever the last run happened to produce and the gate would pass by
// construction — a machine that agrees with itself. _results/manifest.json is a
// report; scripts/sec-selftest-baseline.json is the contract.
//
// ---------------------------------------------------------------------------
// ★ Why the A1 arm's hard gate is STATIC, and why that is not a skip
// ---------------------------------------------------------------------------
// A1 is the ReDoS arm, and the tempting gate is wall-clock: run
// sec-a1-redos.mjs / sec-a1-probe.mjs and fail when T(n) climbs. That gate is
// refused here. Both scripts measure elapsed time on a shared GitHub runner,
// where a noisy neighbour moves a 40 ms measurement by more than any regression
// would; a self-hardening gate that cries wolf every fifth build gets marked
// `continue-on-error` within a month and then it protects nothing. The gate's
// credibility IS its product.
//
// The other tempting gate is `recheck`. sec-a1-catalog.mjs says so itself in its
// header: recheck is not a devDependency (it pulls a JVM jar), it is installed
// with `npm install --no-save recheck` only when the experiment is run, and
// without it the script emits `recheck: {available:false}`. On a default CI
// runner it is therefore unavailable.
//
// "recheck is missing, so skip A1" is exactly the vacuous pass this repo forbids.
// So A1 is gated on the part that is always available, always deterministic, and
// that no timing test can see:
//
//   the ATTACK SURFACE CENSUS — how many rules, how many compiled patterns, and
//   WHICH patterns carry a catastrophic shape (nested quantifier / adjacent
//   unbounded quantifiers over overlapping classes / quantified overlapping
//   alternation), pinned as a SET at (ruleId, patternIndex, hit-ids) grain.
//
// This catches the §9.4 accident directly — 「新ルールで super-linear が混入した
// ら fail」 — and it catches it on the day the rule lands, not on the day someone
// happens to write an attack string that reaches its worst case. The complement
// is already covered: packages/analyzer-core/src/redos-invariant.test.ts scans a
// large adversarial battery under `npm test` and asserts the scan stays inside
// DESIGN §11.1's budget. That test can only see patterns its battery happens to
// attack; this census sees every pattern that compiles IN THE TWO RULE LAYERS,
// under the coverage statement below. Neither subsumes the other, and the timing
// half deliberately lives where a generous per-test budget is affordable rather
// than inside a gate that must never flake.
//
// ★ WHICH LAYERS, EXACTLY — the history of this sentence is the reason it is now
// this specific.
//
// It used to read "every pattern that compiles", full stop, and that was false.
// `scripts/sec-a1-catalog.mjs:82` sets `RULES_ENTRY =
// 'packages/rules/dist/index.js'` and enumerates `allRules` from it;
// `packages/analysis-graph` — the cross-file design-smell layer, which ships in
// the CLI and the Action and whose rules are regex-driven just like the core ones
// — was never loaded, so a catastrophic pattern added to a cross-file rule left
// every gate green. That was recorded as MEASURED LIMIT 8 and left standing,
// with the argument that extending the census needed a reflective probe surface
// on `CrossFileRule` and was therefore a rule-interface change.
//
// ★ THAT ARGUMENT WAS WRONG, AND IT WAS MEASURED TO BE WRONG. No interface
// change was needed. `analyze(ctx)` takes a `ProjectIndex`, and the package
// already exports `collectProjectFiles` / `buildProjectIndex` / `createBudget`;
// building an index over `samples/crossfile-fixtures` and calling `analyze`
// directly gives the `RegExp.prototype.exec` hook exactly as much to hook as
// `match(ctx)` does — measured, 332 (rule, pattern) pairs across all 11
// registered cross-file rules, 0 rules silent, 0 invocation errors. The limit
// was a design claim held without an experiment, and it survived two releases
// while the cross-file registry grew from four rules to eleven.
//
// `scripts/sec-a1-crossfile-catalog.mjs` is that census, gated here by
// `a1:crossfile-surface-census`, `a1:crossfile-shape-suspicious-set` and
// `a1:crossfile-probe-liveness`. What it does NOT cover is written down in
// MEASURED LIMIT 8, which is now a statement of the residue rather than of the
// whole hole.
//
// recheck is still wired in: when it IS available the gate additionally checks
// its super-linear rule set against the baseline. When it is not, that ONE gate
// reports `unmeasured` — never `pass` — and the baseline records
// `measured: false` with the reason, so a green A1 can never be misread as
// "recheck says the regexes are safe". The inverse is a hard failure: a baseline
// that claims `measured: true` while recheck is absent means a promised
// measurement was not made, and that fails the build.
//
// ---------------------------------------------------------------------------
// ★ Why SETS, not scalars
// ---------------------------------------------------------------------------
// packages/analyzer-core/src/embedded-samples.test.ts gates
// samples/embedded/vulnerable with `toBeGreaterThanOrEqual(18)` and says why: a
// floor moves up when a rule is added instead of failing brittlely. That is the
// right call for a floor — and it is structurally blind to SET DRIFT. Twenty-six
// findings where VG-MEM-004 silently stopped firing and two VG-EMB-021 dupes
// appeared is still 26, still ≥ 18, still green, and the product lost a rule.
//
// So the corpus arm pins the MULTISET of `ruleId@file` — sorted, duplicates
// preserved. Sorted-array equality is multiset equality, so it catches both a
// vanished finding and a duplicated one, and the failure names the exact keys
// that appeared and disappeared. A plain set would have lost the multiplicity
// and with it the "two dupes replaced two losses" case above.
//
// Line numbers are deliberately NOT in the key. They move when a fixture is
// reformatted, which is a change to the fixture and not to the detector, and a
// gate that fails on reindentation teaches people to regenerate the baseline
// without reading it.
//
// ---------------------------------------------------------------------------
// ★ Why the corpus SCALE is pinned exactly
// ---------------------------------------------------------------------------
// This is the failure mode that makes a robustness gate actively dangerous. If a
// generator quietly degrades — a transform stops applying, the syntax gate
// starts rejecting everything, SOURCE_DIRS resolves to nothing — it emits a tiny
// or empty corpus. ER is then computed over almost nothing, lands at 0.0, sails
// under the ceiling, and the build goes green while the experiment measures
// air. An empty corpus is the strongest possible "pass" and the weakest possible
// evidence.
//
// So the generated scale (source files, pairs, transformed files, transform
// count, and the file count read back off disk) is pinned EXACTLY, not as a
// floor. A floor would still let a transform stop applying to half the
// population while another one compensates — the ER numerator and denominator
// both move and the headline barely twitches. Exact pins mean adding a transform
// is a deliberate baseline edit, reviewed in the same diff as the transform.
//
// ---------------------------------------------------------------------------
// ★ Directionality: which way is a regression?
// ---------------------------------------------------------------------------
//   B1 / ER  — evasion rate. Higher is worse. Ceiling gate.
//              Plus a FLOOR on ΔER = ER(pre-D2) − ER(shipped): that is how much
//              of the evasion the D2 canonicalization pre-pass absorbs. A change
//              that quietly disables D2 leaves ER unchanged in both arms and
//              slips past a pure ceiling; ΔER collapsing to 0 catches it.
//   B3 / CR  — concealment rate. Higher is worse. Ceiling gate on the worst-case
//              row's gated CR, plus a FLOOR on the D1 reduction
//              (CR_ungated − CR_gated) for the same reason: D1 is the severity
//              floor that makes the gated CR 0, and its removal shows up as the
//              reduction shrinking, not as CR rising above a ceiling it was
//              already under.
//              A naive reading of 「CR が baseline 下限を割ったら fail」 as "gated
//              CR must not FALL" would be wrong — a falling CR is the defence
//              working. The quantity with a genuine lower bound is the
//              reduction, and that is what is floored here.
//
// ---------------------------------------------------------------------------
// ★ MEASURED LIMITS (things that were checked and came back inconvenient)
// ---------------------------------------------------------------------------
//  1. sec-b1-er-eval.mjs EXITS 0 EVEN WHEN ITS OWN ASSERTIONS ARE BROKEN. Its
//     tail writes the JSON and prints "⚠ BROKEN" with no process.exit. Gating on
//     the child's exit code alone is therefore a vacuous pass, and this script
//     reads `assertionsAllOk` / `assertionsBroken` / `structuralViolations` out
//     of the JSON instead. Same for sec-b3-cr-eval.mjs.
//  2. THE B1 SCALE PIN HAS AN ENVIRONMENT DEPENDENCY. The generator's G0 syntax
//     gate spawns `python3 -m py_compile`; on this tree 201 of 416 transformed
//     files were validated by it and 0 pairs were rejected at G0. If python3 is
//     absent the spawn fails, `checkSyntax` records `failed`, and those 201
//     pairs are DROPPED — the exact scale pin then fails for an environmental
//     reason. It is not hidden: a scale mismatch prints the rejection-stage
//     census and the syntax-tool census beside it, so the failure reads
//     "608 transform-gate, 201 G0-syntax (python3 -m py_compile)" instead of an
//     unexplained 215 ≠ 416. ubuntu-latest ships python3, which is why the pin
//     is exact rather than weakened to a floor.
//  3. PINNING THE SHAPE-SUSPICIOUS RULE COUNT WOULD BE TOO COARSE.
//     a1-regex-catalog.json reports `suspiciousRulesByShape: 4`, but those 4
//     rules carry 7 suspicious PATTERNS (VG-QUAL-007 alone has three). An eighth
//     suspicious pattern added to an already-suspicious rule leaves the rule
//     count at 4. The pin is therefore at (ruleId, patternIndex, hit-ids) grain.
//  4. b3-cr.json CARRIES A CLOCK READ (`provenance.evaluator.generatedAt`). The
//     gated `observed` object copies metric fields only and never a provenance
//     block, so two runs of this script produce an identical `observed` and an
//     identical `observedDigest`. Host provenance lives in the ungated
//     `environment` block of _results/manifest.json.
//  5. THE _results LAYER WAS ALREADY STALE WHEN THIS WAS WRITTEN, which is the
//     concrete argument for the two-layer split above rather than a theoretical
//     one. The `a1-regex-catalog.json` sitting in `_results/` before the first
//     run of this script reported 47 rules / 84 patterns / `recheck.available:
//     true`; regenerating it against the current tree gives 71 rules / 127
//     patterns / `recheck.available: false`. Twenty-four rules and forty-three
//     patterns of attack surface had appeared since that file was written, and
//     nothing said so. A gate that had taken `_results/` as its expectation
//     would have been comparing today's engine against a snapshot of an engine
//     from before the embedded rules existed.
//     The same comparison is reassuring in the other direction: the pre-existing
//     `b1-er-eval.json` and `b3-cr.json` — produced by someone else, on an
//     earlier run — carry ER 0.240506/0.189873 over 416 pairs and worst-case CR
//     1→0 over 394 pairs, which is exactly what regeneration reproduced. The
//     baseline numbers below are therefore not an artefact of one run on one
//     machine.
//  6. NOT VERIFIED ON THE CI PLATFORM. Every number in the baseline was recorded
//     on win32 / node v24, and the CI job runs ubuntu-latest / node 20. Nothing
//     the gate reads is documented as version-dependent — regex semantics, the
//     rule catalogue, the ER/CR arithmetic and the finding sets are all pure JS
//     over tracked inputs — but "should be identical" is a prediction, not a
//     measurement, and the one plausible divergence is real: the B1 scale pin
//     depends on `python3` being present (limit 2 above) and on `node --check`
//     accepting the same goal for the same bytes. The baseline therefore records
//     `recordedFrom.{nodeVersion,platform}` so a first-run CI failure can be read
//     as "recorded elsewhere" instead of as a regression. If it does diverge, the
//     fix is to re-record on the CI platform — never to loosen the pin.
//  7. THE CROSS-FILE LAYER IS OUT OF SCOPE HERE, deliberately — BUT THE RULE
//     LAYER'S BEHAVIOUR OVER THE CROSS-FILE CORPORA IS NOT, AND USED TO BE.
//     `packages/analysis-graph` is a package this script does not load; folding
//     the graph in would put a graph dependency in the middle of a rule-layer
//     gate, so the cross-file RULES stay in their own suites. That much is
//     unchanged.
//     ★ What changed (#34 CFGATE, 2026-08-03): the corpora those rules are
//     calibrated against are still ordinary directories of source, and
//     `vibeguard <dir>` in its default mode runs the RULE layer over them. That
//     output is what a user sees, and nothing was checking it. Measured before
//     deciding: the rule layer produces 8 findings over the 734 files of
//     `samples/crossfile-fixtures` (4 of them the Django negative control
//     described at CORPUS_DIRS), and 0 over `samples/crossfile-safe` and
//     `samples/design-safe`.
//     `samples/design-safe` is left to `security-scan.yml`, which already gates
//     it at zero through the packaged CLI; adding a second authority for the
//     same contract is how two numbers with the same name start disagreeing.
//     ⚠ CORRECTED TWICE, and the second correction is the one that closed it.
//     (1) This comment originally said `security-scan.yml` covered
//     `samples/crossfile-safe` too. It does not: the samples job has eight steps
//     (safe, vulnerable, embedded × 2, design-safe, design-smells, proto-safe,
//     proto-pollution) and none of them names any cross-file corpus. The zero was
//     real and nothing held it.
//     (2) #49 XFSAFE-GATE then pinned `crossfile-safe` AND `crossfile-vulnerable`
//     in CORPUS_DIRS below. The reasoning that left them unpinned at (1) — "the
//     fix belongs in the job that owns the packaged-CLI contract, adding it here
//     makes two authorities" — was wrong on its own terms: the two-authority
//     objection is why `samples/design-safe` stays out, and design-safe already
//     HAS an authority. These two had none, so this adds the first, not the
//     second. Recorded rather than rewritten, because the failure being described
//     is a comment that asserted a gate into existence, and deleting the trail
//     would leave the same claim standing with nothing behind it.
//     Recorded so "the corpus arm covers the corpora" is not read as covering
//     the cross-file RULES — it does not, and limit 8 is where that gap lives.
//  8. THE A1 CENSUS NOW COVERS BOTH RULE LAYERS — THIS IS WHAT IT STILL MISSES.
//     This limit used to read "the census covers `packages/rules` only … a
//     super-linear pattern added to a cross-file rule passes every gate here",
//     and that was true and growing: `packages/analysis-graph` held 4 cross-file
//     rules when it was written and 11 when it was closed.
//     `scripts/sec-a1-crossfile-catalog.mjs` closes it in two arms and three
//     gates. MEASURED at the time of writing: 11 registered cross-file rules,
//     0 rule-shaped exports outside the registry, 23 built files carrying 194
//     regex literals and 24 `new RegExp(` construction sites, 332 (rule, pattern)
//     pairs executed over 130 fixture projects, and 0 shape-suspicious patterns
//     in either arm. Falsified by construction, on a scratchpad copy: injecting
//     `/(\s+)+$/` as a literal moves `staticLiterals` 194→195 and puts 4 entries
//     in the suspicious set (both new gates fail); injecting the same pattern via
//     `new RegExp(String.raw`(\s+)+$`)` leaves `staticLiterals` at 194 — no
//     literal scan can see it — and is caught by the runtime arm instead.
//     ★ THE RESIDUE, which is what this limit now records:
//      8a. A pattern CONSTRUCTED in a branch no fixture reaches is counted (its
//          `new RegExp(` site is in the static census) but NOT shape-checked,
//          because nothing resolves its interpolations. Measured: injecting
//          `(\s+)+$` into a function no fixture calls moves
//          `staticConstructionSites` 24→25, so `a1:crossfile-surface-census`
//          FAILS and forces a deliberate baseline edit — but
//          `a1:crossfile-shape-suspicious-set` stays green and the catalogue's
//          own `--check` exits 0. The count is the whole defence there.
//      8b. The dynamic pattern COUNT is a function of the fixture tree, not of
//          the build (332 pairs over 130 fixture projects in the working tree
//          that recorded this, 270 over the 86 tracked in git at that moment), so
//          it is FLOORED, not pinned. A driver that half-degrades stays green
//          until it crosses the floor; the exact checks beside it (every rule
//          executed a pattern, four named product regexes observed) are what make
//          a degradation legible before then.
//      8c. No automaton oracle. `recheck` is wired into the CORE catalogue only;
//          the cross-file arm is shape-heuristic only, so its 0 suspicious
//          patterns is a claim about SHAPES and not a proof of linearity.
//      8e. The construction-site count is TEXTUAL and does not know what a
//          comment is: the scan counts occurrences of the constructor token in
//          the built JS, so PROSE mentioning it moves the number. Found the
//          hard way on 2026-08-03 — a comment added to `authz-lexicon.ts`,
//          explaining that the patterns below are constructed rather than
//          literal, took `staticConstructionSites` 24 → 25 and failed this gate.
//          The gate was right to fail (it cannot tell prose from code) and the
//          comment was reworded rather than the baseline raised. If this gate
//          fails and the delta is 1, check whether someone just wrote the token
//          in a sentence before assuming a regex was added.
//      8d. `packages/analysis-graph`'s non-rule regexes (structure indexer,
//          dependency graph, symbol table, taint) ARE in the static census — they
//          run over attacker-sized file content too — and are captured at runtime
//          under the pseudo-rule `(project-index)`. They are NOT attributed to any
//          rule, because they belong to none.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { scanPath } from '@vibeguard/analyzer-core';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_BASELINE = 'scripts/sec-selftest-baseline.json';
const RESULTS_DIR = 'security-experiment/_results';
const DEFAULT_MANIFEST_OUT = `${RESULTS_DIR}/manifest.json`;

const B1_MANIFEST = `${RESULTS_DIR}/b1-corpus-manifest.json`;
const B1_EVAL = `${RESULTS_DIR}/b1-er-eval.json`;
const B1_CORPUS_DIR = 'security-experiment/track-b-detection-robustness/b1-evasion/corpus';
const B3_MANIFEST = `${RESULTS_DIR}/b3-corpus-manifest.json`;
const B3_EVAL = `${RESULTS_DIR}/b3-cr.json`;
const B3_CORPUS_DIR = 'security-experiment/track-b-detection-robustness/b3-suppression-abuse/corpus';
const A1_CATALOG = `${RESULTS_DIR}/a1-regex-catalog.json`;
const A1_CROSSFILE_CATALOG = `${RESULTS_DIR}/a1-crossfile-regex-catalog.json`;

// The corpora the rule layer is calibrated against. Order is fixed because it is
// the reporting order; the gate ids are derived from these paths.
const CORPUS_DIRS = [
  'samples/safe',
  'samples/vulnerable',
  'samples/embedded/safe',
  'samples/embedded/vulnerable',
  // ★ #34 CFGATE — the cross-file fixture tree, scanned by the RULE LAYER.
  //
  // This corpus exists for `packages/analysis-graph`, and its own suites run the
  // cross-file rules over it. Nothing ran the SINGLE-FILE rules over it, which is
  // a different question and the one a user actually asks: `vibeguard <dir>` in
  // its default mode runs the rule layer, so whatever the rule layer says about
  // these 734 files is output somebody sees, and no gate was looking at it.
  //
  // It was not empty. `smell-010-py-neg-django/shop/views.py` produces four
  // `VG-SMELL-012` at medium — a fixture whose docstring declares that
  // authorization is centralised in `urls.py` and `LoginRequiredMixin`. Both
  // things are true at once: it is a valid negative control for VG-SMELL-010
  // (which stays silent), and it really does compare a role to a string literal
  // four times, which is what VG-SMELL-012 is about. The finding is not the
  // defect; the defect was that nobody would have noticed either way.
  //
  // Pinned as a SNAPSHOT rather than gated as `-eq 0` deliberately. A count floor
  // of zero over a directory of negative controls is the vacuous-pass shape this
  // file already had to close once (see `files` below): it passes on an empty
  // tree, and it also forces the reading that every finding here is a bug, which
  // the Django case shows is false. The snapshot says what the rule layer says
  // TODAY, and any movement — a new fixture that fires, a rule that starts
  // reaching in here, a negative control that stops being negative — is a diff a
  // human reads.
  'samples/crossfile-fixtures',
  // ★ #49 XFSAFE-GATE — the two cross-file DEMO corpora, for the same reason and
  // by the same mechanism as the fixture tree above.
  //
  // #34 pinned `crossfile-fixtures` and left these two alone on the strength of a
  // sentence that turned out to be false: the comment at limit 7 asserted that
  // `security-scan.yml` already gated `crossfile-safe`, and it does not — the
  // samples job has eight steps and none of them names any cross-file corpus.
  // Nothing anywhere read the rule layer's output over these directories.
  //
  // MEASURED before pinning (default mode, `config: false`, this checkout):
  // `crossfile-safe` 0 findings over 11 files, `crossfile-vulnerable` 0 over 10.
  // Both zeros are real, and until now nothing held either of them.
  //
  // ★ WHY BOTH, WHEN THE ITEM ONLY NAMED THE SAFE HALF. `crossfile-vulnerable`
  // measured zero as well, from the same absence of a gate. Pinning one and not
  // the other would leave the identical hole open next to a closed one, which is
  // how the original false sentence came to be believed in the first place.
  //
  // ★ WHY HERE AND NOT IN `security-scan.yml`. Three reasons, in order of weight:
  //   1. A `-eq 0` step passes over an EMPTIED directory. These corpora are 11 and
  //      12 files — the size at which "someone moved the fixtures" is a live
  //      failure mode. The `files` census below fails first and names the missing
  //      fixtures; a count floor of zero cannot.
  //   2. `README.md` states as a DESIGN decision that the cross-file corpora are
  //      not in the samples job, because their own rules run only behind
  //      `--include-design-smells`. Adding them there would contradict a
  //      documented decision; adding them here does not, because what is pinned
  //      is the SINGLE-FILE rule layer's output, which is a different question
  //      from the one that sentence answers.
  //   3. #34 already answered this exact question for `crossfile-fixtures` and
  //      answered it here. A second dialect of the same gate is how two numbers
  //      with the same name start disagreeing.
  // The "two authorities" objection that keeps `samples/design-safe` out of this
  // list does not apply: design-safe already HAS an authority in the samples job,
  // and these two had none. This adds the first, not the second.
  'samples/crossfile-safe',
  'samples/crossfile-vulnerable',
];

export const ARMS = ['corpus', 'a1', 'b1', 'b3'];

// Files the corpus generators drop beside the corpus that are not corpus
// members. `.gitattributes` is written by sec-b1-gen-corpus.mjs so a CRLF
// round-trip cannot move a line number; counting it would make the file pin
// disagree with the manifest by exactly one.
const NON_CORPUS_FILES = new Set(['.gitattributes']);

const slash = (p) => String(p).replace(/\\/g, '/');

// ------------------------------------------------------------------- argv ----
function parseArgs(argv) {
  const at = (flag, fallback) => {
    const i = argv.indexOf(flag);
    return i === -1 || i + 1 >= argv.length ? fallback : argv[i + 1];
  };
  const armsRaw = at('--arms', ARMS.join(','));
  const arms = armsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = arms.filter((a) => !ARMS.includes(a));
  return {
    baselinePath: at('--baseline', DEFAULT_BASELINE),
    manifestOut: at('--manifest-out', DEFAULT_MANIFEST_OUT),
    arms,
    unknownArms: unknown,
    // Test/iteration seam. Consumes an EXISTING generator manifest instead of
    // regenerating (24 s for B1). Any run that uses it is marked
    // `authoritative: false` in the record, because the corpus it scored is not
    // one this run produced from tracked inputs.
    b1Manifest: at('--b1-manifest', null),
    b3Manifest: at('--b3-manifest', null),
    // Public-surface redaction. The B1/B3 gates compare measured evasion and
    // concealment rates against the baseline, and those rates are the headline
    // numbers of an unpublished write-up. On a public runner every one of them
    // reaches three readable surfaces at once — the raw job log (this function
    // prints to stdout and CI tees it), the run page's step summary, and any
    // uploaded artefact. Redaction keeps the gate and drops the reading: the
    // verdict, the gate id and the failed-gate list still cross, so a
    // regression is still visible and still red, but nobody learns the rate.
    // Off by default, because a maintainer running this locally needs the
    // numbers to act on a failure.
    redactMetrics: argv.includes('--redact-metrics') || process.env.VG_SELFTEST_REDACT === '1',
  };
}

// Gates whose reading is a measurement from the withheld arms. Matched on the
// id prefix rather than a list, so a gate added later to either arm inherits
// the redaction instead of quietly publishing a new number.
const REDACTED_ARM_PREFIXES = ['b1:', 'b3:'];
const isRedactedGate = (id) => REDACTED_ARM_PREFIXES.some((p) => String(id).startsWith(p));
const REDACTED = '[redacted: measured value withheld on a public surface]';

// ------------------------------------------------------------------- utils ---
/** Deterministic JSON: object keys sorted at every depth, array order kept. */
export function canonicalJson(value) {
  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = walk(v[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value));
}

function digestOf(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex').slice(0, 16);
}

/**
 * Sorted, repo-relative file list under `dir`, excluding generator metadata.
 *
 * The census the corpus gate needs, and deliberately a LIST rather than the
 * count `countCorpusFiles` already provides: the failure this closes includes
 * renaming `weak_hash.py` to `weak_hash.txt`, which the scanner then never
 * opens and which a count cannot see.
 */
function listCorpusFiles(dir) {
  const abs = resolve(REPO_ROOT, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  const walk = (at, prefix) => {
    for (const entry of readdirSync(at).sort()) {
      const full = join(at, entry);
      const rel = prefix ? `${prefix}/${entry}` : entry;
      if (statSync(full).isDirectory()) walk(full, rel);
      else if (!NON_CORPUS_FILES.has(entry)) out.push(rel);
    }
  };
  walk(abs, '');
  return out.sort((a, b) => a.localeCompare(b));
}

/** Recursive file count under `dir`, excluding the generators' own metadata. */
function countCorpusFiles(dir) {
  const abs = resolve(REPO_ROOT, dir);
  if (!existsSync(abs)) return 0;
  let n = 0;
  for (const entry of readdirSync(abs).sort()) {
    const full = join(abs, entry);
    if (statSync(full).isDirectory()) n += countCorpusFiles(full);
    else if (!NON_CORPUS_FILES.has(entry)) n += 1;
  }
  return n;
}

function readJson(path) {
  const abs = resolve(REPO_ROOT, path);
  if (!existsSync(abs)) throw new Error(`file not found: ${slash(path)}`);
  return JSON.parse(readFileSync(abs, 'utf8'));
}

/** Last few non-empty lines of a child's output — enough to explain a failure. */
function tail(text, n = 6) {
  return String(text ?? '')
    .split('\n')
    .map((l) => l.trimEnd())
    .filter(Boolean)
    .slice(-n)
    .join('\n');
}

/**
 * Run one of the sec-* scripts as a child process.
 *
 * Deliberately a child process rather than a dynamic import: every one of those
 * scripts is a top-level program that calls `process.exit` on its own error
 * paths (sec-b1-er-eval.mjs's `fail()`, sec-a1-catalog.mjs's
 * `rulesWithoutLiteral` abort). Importing them would take this process down with
 * them, and the whole point here is to turn their failure into a NAMED gate
 * verdict rather than an opaque crash.
 */
function runScript(script, args) {
  const r = spawnSync(process.execPath, [script, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    script: slash(script),
    args,
    status: r.status,
    ok: r.status === 0,
    stdoutTail: tail(r.stdout),
    stderrTail: tail(r.stderr, 12),
    spawnError: r.error ? String(r.error.message ?? r.error) : null,
  };
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------
/**
 * Load and structurally validate the tracked baseline.
 *
 * Fails LOUD and specifically. "Baseline missing" is the single most likely way
 * this gate degrades into a no-op — a rename, a bad path, a workspace that never
 * checked the file out — and the one outcome it must never produce is a silent
 * skip. Every error path here throws; main() turns the throw into a non-zero
 * exit with the reason on stderr.
 */
export function loadBaseline(path) {
  const abs = resolve(REPO_ROOT, path);
  if (!existsSync(abs)) {
    throw new Error(
      `baseline not found at ${slash(path)}.\n` +
        `  The self-hardening gate has nothing to compare against, which is a FAILURE, not a skip:\n` +
        `  a run with no baseline can neither pass nor fail a threshold, so it must not report a pass.\n` +
        `  The baseline is tracked in git — restore it, or regenerate it deliberately and review the diff.`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(abs, 'utf8'));
  } catch (err) {
    throw new Error(`baseline at ${slash(path)} is not valid JSON: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.gates || typeof parsed.gates !== 'object') {
    throw new Error(`baseline at ${slash(path)} has no "gates" object — it cannot gate anything.`);
  }
  const ids = Object.keys(parsed.gates);
  if (ids.length === 0) {
    throw new Error(`baseline at ${slash(path)} declares 0 gates — an empty contract passes everything.`);
  }
  for (const id of ids) {
    const arm = String(id).split(':')[0];
    if (!ARMS.includes(arm)) {
      throw new Error(
        `baseline gate "${id}" names arm "${arm}", which this harness does not run (known arms: ${ARMS.join(', ')}).`,
      );
    }
  }
  const optional = parsed.optionalGates ?? [];
  if (!Array.isArray(optional)) {
    throw new Error(`baseline "optionalGates" must be an array of gate ids.`);
  }
  for (const id of optional) {
    if (!ids.includes(id)) {
      throw new Error(`baseline "optionalGates" names "${id}", which is not a declared gate.`);
    }
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Arm: corpus — the finding SET of every corpus the rule layer is calibrated on
// ---------------------------------------------------------------------------
/**
 * `config: false` mirrors packages/analyzer-core/src/embedded-samples.test.ts:
 * a `.vibeguard.json` sitting anywhere above the samples would silently change
 * which rules run, and the snapshot is supposed to describe the SHIPPED ruleset,
 * not this checkout's local configuration.
 */
async function runCorpusArm() {
  const dirs = {};
  for (const dir of CORPUS_DIRS) {
    const abs = resolve(REPO_ROOT, dir);
    if (!existsSync(abs)) {
      // A missing corpus is a failure, not an empty snapshot: an empty snapshot
      // would compare equal to a baseline of `[]` and pass.
      dirs[dir] = { present: false, findings: null, count: null };
      continue;
    }
    const res = await scanPath(abs, { config: false });
    const findings = res.findings
      .map((f) => `${f.ruleId}@${slash(f.filePath)}`)
      .sort((a, b) => a.localeCompare(b));
    // ★ WHY `filesScanned` EXISTS, AND WHY ITS ABSENCE WAS THE ONE VACUOUS PASS
    // LEFT IN THIS SCRIPT.
    //
    // The check above catches a corpus directory that is GONE. It does not
    // catch one that is still there and EMPTY — deleted fixtures, renamed
    // extensions, a directory moved one level down. For the two false-positive
    // corpora (`samples/safe`, `samples/embedded/safe`) the pinned snapshot is
    // `[]`, so an empty scan produces `[]`, compares equal, and the gate
    // reports that the zero-false-positive contract still holds while nothing
    // was examined at all. That is precisely the failure this file forbids for
    // B1 and B3 — see "★ Why the corpus SCALE is pinned exactly" in the header,
    // which pins `sourceFiles`/`pairs`/`corpusFiles` for exactly this reason —
    // and it was not applied to the corpus arm, which is the arm whose whole
    // claim is that the product is calibrated against real fixtures.
    //
    // `files` is a DIRECTORY CENSUS, not the scanner's own account of what it
    // opened — `ScanResponse` carries no scanned-file count, and deriving one
    // by re-walking with a private copy of the admission rules is the exact
    // divergence `project.ts` documents as a bug. So the witness is independent
    // of the finding list (a snapshot may legitimately be empty; the fixture
    // list may not) without pretending to be a second opinion from the scanner.
    //
    // ★ WHAT THIS DOES AND DOES NOT WITNESS. It closes deleted, moved, and
    // renamed fixtures — including the rename that keeps the count the same and
    // changes the extension, which is why this is a list and not a number. It
    // does NOT witness a file that is present, named correctly, and skipped by
    // the scanner for some other reason; nothing short of a count from the
    // scanner itself would, and adding one is a schema change this gate does
    // not justify on its own.
    dirs[dir] = {
      present: true,
      findings,
      count: findings.length,
      files: listCorpusFiles(dir),
    };
  }
  return dirs;
}

/**
 * A1, cross-file half — the census over `packages/analysis-graph`.
 *
 * ★ WHY THIS IS A SEPARATE CHILD AND A SEPARATE SET OF GATES.
 *
 * MEASURED LIMIT 8 used to say the A1 census covers `packages/rules` only, and
 * that a super-linear pattern added to a cross-file rule passes every gate here.
 * This closes most of that; what it deliberately does NOT do is fold the
 * cross-file numbers into `a1:surface-census`, because the two layers are not
 * measurable on the same axis:
 *
 *   - a core rule's pattern set is a function of the BUILD (one inert probe
 *     string reaches all of them), so it can be pinned exactly;
 *   - a cross-file rule builds patterns FROM THE INPUT it analyses
 *     (`new RegExp(String.raw`\b${escaped}\b`)` over identifiers read out of the
 *     file), so the count of patterns it executes is a function of the FIXTURE
 *     TREE. Measured: 332 (rule, pattern) pairs over the 130 fixture projects in
 *     a working tree, 270 over the 86 that were tracked at the time of writing.
 *
 * Pinning that number exactly would produce a gate that fails whenever a fixture
 * is added — and a gate people re-record without reading is worse than no gate.
 * So the cross-file arm is pinned on the axis that IS a function of the build
 * (regex literals and `new RegExp(` construction sites in the built package) and
 * floored on the axis that is not, with the liveness properties that make a low
 * number legible — every rule executed at least one pattern, and four named
 * product regexes were observed — checked exactly.
 */
function runA1CrossFileArm() {
  const run = runScript('scripts/sec-a1-crossfile-catalog.mjs', []);
  if (!run.ok) return { ran: false, run, summary: null, shapeSuspicious: null };
  let cat;
  try {
    cat = readJson(A1_CROSSFILE_CATALOG);
  } catch (err) {
    return { ran: false, run: { ...run, spawnError: err.message }, summary: null, shapeSuspicious: null };
  }
  const s = cat.summary ?? {};
  return {
    ran: true,
    run,
    summary: {
      crossFileRules: s.crossFileRules ?? null,
      // A rule-shaped export that is NOT in `crossFileRules` is a candidate rule
      // (index.ts documents the state). It is un-shipped, so it is not gated as
      // surface — but its APPEARANCE is gated, because a candidate silently
      // joining the registry is exactly the event this census exists to notice.
      exportedUnregisteredRuleIds: (s.exportedUnregisteredRuleIds ?? []).length,
      staticFilesScanned: s.static?.filesScanned ?? null,
      staticLiterals: s.static?.literals ?? null,
      staticConstructionSites: s.static?.constructionSites ?? null,
      staticUncompilable: s.static?.uncompilable ?? null,
      dynamicPatternPairs: s.dynamic?.distinctRulePatternPairs ?? null,
      dynamicFixtureProjects: s.dynamic?.fixtureProjects ?? null,
      dynamicRulesWithNoPattern: (s.dynamic?.rulesWithNoPattern ?? []).length,
      dynamicAnalyzeErrors: s.dynamic?.analyzeErrors ?? null,
      positiveControlOk: s.positiveControl?.ok === true,
      positiveControlMissing: [...(s.positiveControl?.missing ?? [])].sort(),
      crossCheckDynamicNotStatic: s.crossCheck?.dynamicNotStatic ?? null,
      crossCheckStaticNotDynamic: s.crossCheck?.staticNotDynamic ?? null,
      // Carried verbatim (not reduced to a boolean) so a FAIL can name which
      // canary went missing. `?? null` rather than `?? {ok:true}`: an older
      // catalogue that predates the canary must FAIL this gate, not inherit a
      // pass — the whole point is that silence is not evidence.
      shapeChecker: s.shapeChecker ?? null,
    },
    shapeSuspicious: [...(cat.shapeSuspicious ?? [])].sort((a, b) => String(a).localeCompare(String(b))),
  };
}

// ---------------------------------------------------------------------------
// Arm: A1 — static attack-surface census over the shipped rule regexes
// ---------------------------------------------------------------------------
function runA1Arm() {
  // Independent of the core census, and computed FIRST so it is present on every
  // return path below. The two censuses cover different packages and fail for
  // different reasons; a broken `packages/rules` build must not make the
  // cross-file gates report "did not run" and hide which half is actually
  // broken.
  const crossFile = runA1CrossFileArm();
  const run = runScript('scripts/sec-a1-catalog.mjs', []);
  if (!run.ok) {
    return { ran: false, run, crossFile, recheckReason: null, summary: null, shapeSuspicious: null, unreachedRuleIds: null };
  }
  let cat;
  try {
    cat = readJson(A1_CATALOG);
  } catch (err) {
    return {
      ran: false,
      run: { ...run, spawnError: err.message },
      crossFile,
      recheckReason: null,
      summary: null,
      shapeSuspicious: null,
      unreachedRuleIds: null,
    };
  }
  const s = cat.summary ?? {};
  const entries = Array.isArray(cat.entries) ? cat.entries : [];

  // (ruleId, patternIndex, hit-ids) grain — see MEASURED LIMIT 3. Hit ids are
  // included so a pattern that swaps `adjacent-unbounded` for
  // `nested-quantifier` is a visible change and not a silent one.
  const shapeSuspicious = entries
    .filter((e) => e.shape && e.shape.suspicious)
    .map((e) => {
      const hits = (e.shape.hits ?? []).map((h) => String(h.id)).sort();
      return `${e.ruleId}#${e.patternIndex}=${hits.join('+')}`;
    })
    .sort((a, b) => a.localeCompare(b));

  // Rules carrying a source literal the runtime hook never reached. Kept as a
  // multiset of ruleIds (VG-SEC-003 contributes three) rather than a set: a rule
  // growing a second unreached literal is a growth of the un-probed surface.
  const unreachedRuleIds = (s.unreachedLiterals ?? [])
    .map((u) => String(u.ruleId))
    .sort((a, b) => a.localeCompare(b));

  return {
    ran: true,
    run,
    crossFile,
    // `recheck.reason` is deliberately NOT part of `summary`: on this host it is
    // "Cannot find package 'recheck' imported from C:\Users\…", an ABSOLUTE PATH.
    // Anything host-specific inside the gated observation would make the digest
    // differ between machines for a reason that is not a regression. It is kept
    // beside the summary so failure messages can still quote it.
    recheckReason: s.recheck?.reason ?? null,
    summary: {
      totalRules: s.totalRules ?? null,
      rulesWithPatterns: s.rulesWithPatterns ?? null,
      totalPatterns: s.totalPatterns ?? null,
      rulesWithoutLiteral: (s.rulesWithoutLiteral ?? []).length,
      patternsFailingToCompile: (s.patternsFailingToCompile ?? []).length,
      ruleInvocationErrors: (s.ruleInvocationErrors ?? []).length,
      recheckAvailable: s.recheck?.available === true,
      // null when recheck is absent — NOT [] — so "no super-linear rules found"
      // and "nobody looked" are different values in the record.
      recheckSuperLinearRuleIds: s.recheck?.available === true ? [...(s.superLinearRuleIds ?? [])].sort() : null,
    },
    shapeSuspicious,
    unreachedRuleIds,
  };
}

// ---------------------------------------------------------------------------
// Arm: B1 — evasion rate against the shipped detector
// ---------------------------------------------------------------------------
/**
 * Scale is read from the generator manifest BEFORE the evaluator runs, and the
 * file count is read back off disk rather than taken from the manifest. Two
 * reasons, both about the empty-corpus accident:
 *   - the evaluator refuses a 0-pair manifest and exits 1, so scale read only
 *     from the evaluator's output would never see the number that explains WHY;
 *   - a manifest claiming 416 pairs while 3 files reached the disk is a
 *     generator bug the manifest cannot self-report.
 */
function runB1Arm(reuseManifestPath) {
  const gen = reuseManifestPath
    ? { script: '(reused)', args: [], status: 0, ok: true, stdoutTail: '', stderrTail: '', spawnError: null }
    : runScript('scripts/sec-b1-gen-corpus.mjs', ['--out', B1_MANIFEST]);
  const manifestPath = reuseManifestPath ?? B1_MANIFEST;

  let scale = null;
  let syntaxCensus = null;
  let rejectionCensus = null;
  if (gen.ok) {
    try {
      const m = readJson(manifestPath);
      const counts = m.counts ?? {};
      scale = {
        sourceFiles: counts.sourceFiles ?? null,
        pairs: Array.isArray(m.pairs) ? m.pairs.length : (counts.pairs ?? null),
        transformedFiles: counts.transformedFiles ?? null,
        transforms: Array.isArray(m.transforms) ? m.transforms.length : null,
        corpusFiles: countCorpusFiles(B1_CORPUS_DIR),
      };
      // Diagnostics for MEASURED LIMIT 2 — printed beside a scale mismatch so an
      // environmental cause (no python3) is legible instead of mysterious.
      syntaxCensus = {};
      for (const tf of m.transformedFiles ?? []) {
        const k = `${tf.syntaxCheck?.status}|${tf.syntaxCheck?.tool}`;
        syntaxCensus[k] = (syntaxCensus[k] ?? 0) + 1;
      }
      rejectionCensus = {};
      for (const r of m.rejections ?? []) {
        rejectionCensus[r.stage] = (rejectionCensus[r.stage] ?? 0) + 1;
      }
    } catch (err) {
      gen.spawnError = `manifest unreadable: ${err.message}`;
      gen.ok = false;
    }
  }

  const evalRun = gen.ok
    ? runScript('scripts/sec-b1-er-eval.mjs', ['--manifest', manifestPath, '--out', B1_EVAL])
    : { script: 'scripts/sec-b1-er-eval.mjs', args: [], status: null, ok: false, stdoutTail: '', stderrTail: '', spawnError: 'not run: the generator step failed' };

  let metrics = null;
  let integrity = null;
  if (evalRun.ok) {
    try {
      const e = readJson(B1_EVAL);
      const paired = e.overall?.paired?.exists ?? {};
      metrics = {
        // The headline the evaluator itself designates: matched pairs, one
        // shared denominator, `exists` observation, negative controls excluded.
        erFalse: paired.false?.er ?? null,
        erTrue: paired.true?.er ?? null,
        deltaEr: paired.deltaEr ?? null,
        denominatorFalse: paired.false?.denominator ?? null,
        denominatorTrue: paired.true?.denominator ?? null,
      };
      integrity = {
        // MEASURED LIMIT 1: these come from the JSON, not from the exit code.
        censusAllAgree: e.integrity?.censusAllAgree === true,
        mutationAllLive: e.integrity?.mutationTest?.allLive === true,
        assertionsAllOk: e.assertionsAllOk === true,
        assertionsBroken: e.assertionsBroken ?? null,
        assertionsUnmeasured: e.assertionsUnmeasured ?? null,
        structuralViolations: (e.structuralViolations ?? []).length,
        unusablePairs: (e.unusablePairs ?? []).length,
        // NC2 is the noop transform: it changes nothing, so any "evasion" it
        // shows means the harness fabricates concealment. NC1 really removes the
        // vulnerability, so its findings must disappear.
        negativeControlNC2Ok: e.negativeControls?.NC2?.ok === true,
        negativeControlNC1Ok: e.negativeControls?.NC1?.ok === true,
      };
    } catch (err) {
      evalRun.spawnError = `eval output unreadable: ${err.message}`;
      evalRun.ok = false;
    }
  }

  return { gen, evalRun, scale, metrics, integrity, syntaxCensus, rejectionCensus, reused: reuseManifestPath != null };
}

// ---------------------------------------------------------------------------
// Arm: B3 — concealment rate against confidence-based triage
// ---------------------------------------------------------------------------
function runB3Arm(reuseManifestPath) {
  const gen = reuseManifestPath
    ? { script: '(reused)', args: [], status: 0, ok: true, stdoutTail: '', stderrTail: '', spawnError: null }
    : runScript('scripts/sec-b3-gen-corpus.mjs', []);
  const manifestPath = reuseManifestPath ?? B3_MANIFEST;

  let scale = null;
  if (gen.ok) {
    try {
      const m = readJson(manifestPath);
      scale = {
        pairs: Array.isArray(m.pairs) ? m.pairs.length : null,
        transforms: Array.isArray(m.transforms) ? m.transforms.length : null,
        corpusFiles: countCorpusFiles(B3_CORPUS_DIR),
      };
    } catch (err) {
      gen.spawnError = `manifest unreadable: ${err.message}`;
      gen.ok = false;
    }
  }

  const evalRun = gen.ok
    ? runScript('scripts/sec-b3-cr-eval.mjs', ['--manifest', manifestPath, '--out', B3_EVAL])
    : { script: 'scripts/sec-b3-cr-eval.mjs', args: [], status: null, ok: false, stdoutTail: '', stderrTail: '', spawnError: 'not run: the generator step failed' };

  let metrics = null;
  let integrity = null;
  if (evalRun.ok) {
    try {
      const e = readJson(B3_EVAL);
      const wc = e.worstCase ?? null;
      const und = e.byDisclosure?.undeclared ?? null;
      metrics = {
        threshold: e.threshold ?? null,
        // Worst case, never a mean — sec-b3-cr-eval.mjs refuses to emit a pooled
        // average for the same reason SCOPE §2.3 does: an attack that works on
        // one row is not diluted by rows it does not touch.
        worstCaseRow: wc ? `${wc.transform}/${wc.severity}` : null,
        worstCaseCrUngated: wc?.crUngated ?? null,
        worstCaseCrGated: wc?.crGated ?? null,
        worstCaseDenominator: wc?.denominator ?? null,
        // D1's declared defence target: an UNDECLARED disguise must be worth
        // nothing after the severity floor.
        undeclaredCrGated: und?.crGated ?? null,
        undeclaredCrUngated: und?.crUngated ?? null,
        undeclaredDenominator: und?.denominatorGated ?? null,
      };
      integrity = {
        ruleErrors: (e.ruleErrors ?? []).length,
        unresolvedOriginal: e.pairs?.unresolvedOriginal ?? null,
        excludedOptOut: e.pairs?.excludedOptOut ?? null,
        severityRegistryViolations: e.pairs?.severityRegistryViolations ?? null,
        // Cross-check, not a duplicate of the corpus arm: this number is produced
        // by the rule layer directly (allRules + explainContextConfidence) while
        // the corpus arm goes through scanPath. Two independent paths agreeing on
        // samples/safe = 0 and samples/vulnerable = 51 is worth more than either
        // alone; a disagreement would be a real finding.
        sideConstraintsAllOk:
          e.sideConstraints?.safeFindingsOk === true &&
          e.sideConstraints?.vulnerableTotalOk === true &&
          e.sideConstraints?.vulnerableDistributionOk === true,
        pairingAgreement: e.pairingAgreement ?? null,
      };
    } catch (err) {
      evalRun.spawnError = `eval output unreadable: ${err.message}`;
      evalRun.ok = false;
    }
  }

  return { gen, evalRun, scale, metrics, integrity, reused: reuseManifestPath != null };
}

// ---------------------------------------------------------------------------
// Gate evaluation — PURE
// ---------------------------------------------------------------------------
// Split out from the arms deliberately: everything above touches the filesystem
// and spawns children, everything here is a function of (observed, baseline).
// That is what lets scripts/sec-selftest.test.ts drive the impossible-threshold
// and empty-corpus cases without paying 24 s of corpus generation per assertion,
// while the end-to-end exit-code wiring is still covered by real subprocess runs.

const PASS = 'pass';
const FAIL = 'fail';
const UNMEASURED = 'unmeasured';

function gate(id, verdict, { expected = null, actual = null, detail = null, why = null } = {}) {
  return { id, arm: String(id).split(':')[0], verdict, expected, actual, detail, why };
}

/** Sorted-array (multiset) equality, with the symmetric difference for the report. */
function diffMultiset(actual, expected) {
  const count = (xs) => {
    const m = new Map();
    for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
    return m;
  };
  const a = count(actual);
  const b = count(expected);
  const added = [];
  const removed = [];
  for (const [k, n] of a) {
    const d = n - (b.get(k) ?? 0);
    for (let i = 0; i < d; i++) added.push(k);
  }
  for (const [k, n] of b) {
    const d = n - (a.get(k) ?? 0);
    for (let i = 0; i < d; i++) removed.push(k);
  }
  return { added: added.sort(), removed: removed.sort() };
}

/**
 * Exact equality over a small record of scalars, reporting every field that moved.
 *
 * Compares the UNION of the two key sets, not just the baseline's keys. Iterating
 * only over `expected` was the first version of this function and it is a vacuous
 * pass generator: a baseline entry of `{}` — a typo, a half-finished edit, a
 * regenerated file that lost a block — makes every observation compare equal to
 * nothing and the gate reports PASS while checking literally zero fields.
 * Measured, not hypothesised: with `"b1:harness-integrity": {"expected": {}}` the
 * gate passed while the run had never looked at a single integrity flag. So an
 * observed field with no expectation is a FAILURE ("the baseline does not govern
 * this observation"), exactly as an expectation with no observation is.
 */
function diffRecord(actual, expected) {
  const moved = [];
  const keys = [...new Set([...Object.keys(expected ?? {}), ...Object.keys(actual ?? {})])].sort();
  if (keys.length === 0) {
    return ['the baseline entry and the observation are both empty — this gate would check nothing'];
  }
  for (const k of keys) {
    const hasExpected = Object.prototype.hasOwnProperty.call(expected ?? {}, k);
    const hasActual = Object.prototype.hasOwnProperty.call(actual ?? {}, k);
    if (!hasExpected) {
      moved.push(`${k}: observed ${JSON.stringify(actual[k])} but the baseline declares no expectation for it`);
      continue;
    }
    if (!hasActual) {
      moved.push(`${k}: the baseline expects ${JSON.stringify(expected[k])} but the run observed nothing for it`);
      continue;
    }
    if (JSON.stringify(actual[k]) !== JSON.stringify(expected[k])) {
      moved.push(`${k}: expected ${JSON.stringify(expected[k])}, got ${JSON.stringify(actual[k])}`);
    }
  }
  return moved;
}

/**
 * Turn observations + baseline into a verdict per gate.
 *
 * `armsRun` scopes the completeness check: a baseline gate whose arm did not run
 * is not evaluated, but a baseline gate whose arm DID run and produced no
 * verdict is a hard failure (harness drift — someone removed a check and the
 * build stayed green). The converse is also a failure: a verdict with no
 * baseline entry means the baseline is out of date and the new check is
 * ungoverned.
 */
export function evaluateGates(observed, baseline, armsRun) {
  const B = baseline.gates;
  const produced = [];
  const has = (id) => Object.prototype.hasOwnProperty.call(B, id);

  // ------------------------------------------------------------- corpus ----
  if (armsRun.includes('corpus')) {
    for (const dir of CORPUS_DIRS) {
      const id = `corpus:${dir}`;
      if (!has(id)) {
        produced.push(gate(id, FAIL, { detail: 'no baseline entry for this corpus — the baseline is out of date' }));
        continue;
      }
      const exp = B[id].snapshot ?? [];
      const obs = observed.corpus?.[dir] ?? null;
      const why = 'a finding SET that drifts is invisible to a count-based floor (embedded-samples.test.ts is a floor)';
      if (!obs || obs.present !== true || !Array.isArray(obs.findings)) {
        produced.push(gate(id, FAIL, { expected: exp.length, actual: null, detail: `corpus directory ${dir} did not produce a snapshot (missing directory?)`, why }));
        continue;
      }
      // ★ SCALE BEFORE SET — the same ordering B1 and B3 use, and for the same
      // reason. A snapshot of `[]` (the false-positive corpora) compares equal
      // to an empty scan, so without this an emptied `samples/safe` would
      // report that the zero-false-positive contract holds having examined
      // nothing. Checked FIRST so the failure names the missing fixtures rather
      // than a finding-set difference downstream of them.
      const expFiles = B[id].files ?? null;
      if (!Array.isArray(expFiles)) {
        produced.push(gate(id, FAIL, { detail: `baseline entry for ${dir} declares no file census — re-record it; a snapshot alone cannot distinguish "clean" from "empty"`, why }));
        continue;
      }
      const obsFiles = Array.isArray(obs.files) ? obs.files : [];
      if (canonicalJson(obsFiles) !== canonicalJson(expFiles)) {
        const d = diffMultiset(obsFiles, expFiles);
        produced.push(
          gate(id, FAIL, {
            expected: expFiles.length,
            actual: obsFiles.length,
            detail:
              `corpus file census changed, so the finding snapshot describes a different corpus. ` +
              `appeared: ${d.added.length ? d.added.join(', ') : '(none)'}` +
              ` | disappeared: ${d.removed.length ? d.removed.join(', ') : '(none)'}`,
            why: 'an empty or renamed fixture set makes an empty finding snapshot compare equal and pass',
          }),
        );
        continue;
      }
      if (canonicalJson(obs.findings) === canonicalJson(exp)) {
        produced.push(gate(id, PASS, { expected: exp.length, actual: obs.findings.length, why }));
      } else {
        const d = diffMultiset(obs.findings, exp);
        produced.push(
          gate(id, FAIL, {
            expected: exp.length,
            actual: obs.findings.length,
            detail:
              `finding multiset changed. appeared: ${d.added.length ? d.added.join(', ') : '(none)'}` +
              ` | disappeared: ${d.removed.length ? d.removed.join(', ') : '(none)'}`,
            why,
          }),
        );
      }
    }
  }

  // ----------------------------------------------------------------- A1 ----
  if (armsRun.includes('a1')) {
    const a1 = observed.a1 ?? null;
    const armDead = !a1 || a1.ran !== true;
    const armDetail = armDead
      ? `the A1 catalogue did not run: ${a1?.run?.spawnError ?? a1?.run?.stderrTail ?? 'unknown reason'}`
      : null;

    const push = (id, fn) => {
      if (!has(id)) {
        produced.push(gate(id, FAIL, { detail: 'no baseline entry for this gate — the baseline is out of date' }));
        return;
      }
      if (armDead) {
        produced.push(gate(id, FAIL, { detail: armDetail, why: 'an arm that cannot run is a failure, never a skip' }));
        return;
      }
      produced.push(fn(B[id]));
    };

    push('a1:surface-census', (b) => {
      const actual = {
        totalRules: a1.summary.totalRules,
        rulesWithPatterns: a1.summary.rulesWithPatterns,
        totalPatterns: a1.summary.totalPatterns,
      };
      const moved = diffRecord(actual, b.expected ?? {});
      const why = 'a new rule adds regex surface; the census is what makes that surface visible on the day it lands';
      return moved.length === 0
        ? gate('a1:surface-census', PASS, { expected: b.expected, actual, why })
        : gate('a1:surface-census', FAIL, { expected: b.expected, actual, detail: moved.join('; '), why });
    });

    push('a1:shape-suspicious-set', (b) => {
      const exp = b.patterns ?? [];
      const why = '§9.4: 新ルールで super-linear が混入したら fail — pinned at (ruleId, patternIndex, hit-ids) grain';
      if (canonicalJson(a1.shapeSuspicious) === canonicalJson(exp)) {
        return gate('a1:shape-suspicious-set', PASS, { expected: exp.length, actual: a1.shapeSuspicious.length, why });
      }
      const d = diffMultiset(a1.shapeSuspicious, exp);
      return gate('a1:shape-suspicious-set', FAIL, {
        expected: exp,
        actual: a1.shapeSuspicious,
        detail: `appeared: ${d.added.join(', ') || '(none)'} | disappeared: ${d.removed.join(', ') || '(none)'}`,
        why,
      });
    });

    push('a1:unreached-literals', (b) => {
      const exp = b.ruleIds ?? [];
      const why = 'an unreached literal is attack surface the runtime hook cannot measure; growth of that set must be deliberate';
      if (canonicalJson(a1.unreachedRuleIds) === canonicalJson(exp)) {
        return gate('a1:unreached-literals', PASS, { expected: exp.length, actual: a1.unreachedRuleIds.length, why });
      }
      const d = diffMultiset(a1.unreachedRuleIds, exp);
      return gate('a1:unreached-literals', FAIL, {
        expected: exp,
        actual: a1.unreachedRuleIds,
        detail: `appeared: ${d.added.join(', ') || '(none)'} | disappeared: ${d.removed.join(', ') || '(none)'}`,
        why,
      });
    });

    push('a1:catalog-errors', (b) => {
      const actual = {
        rulesWithoutLiteral: a1.summary.rulesWithoutLiteral,
        patternsFailingToCompile: a1.summary.patternsFailingToCompile,
        ruleInvocationErrors: a1.summary.ruleInvocationErrors,
      };
      const moved = diffRecord(actual, b.expected ?? {});
      const why = 'a rule that throws on the probe, or a pattern that does not compile, silently shrinks the measured surface';
      return moved.length === 0
        ? gate('a1:catalog-errors', PASS, { expected: b.expected, actual, why })
        : gate('a1:catalog-errors', FAIL, { expected: b.expected, actual, detail: moved.join('; '), why });
    });

    push('a1:recheck-superlinear', (b) => {
      const id = 'a1:recheck-superlinear';
      const available = a1.summary.recheckAvailable;
      const why = 'recheck is the discovery oracle, not a devDependency (JVM jar); its absence must read as unmeasured, never as safe';
      if (b.measured === true && !available) {
        return gate(id, FAIL, {
          expected: 'recheck available (the baseline claims a recheck measurement)',
          actual: `recheck unavailable: ${a1.recheckReason ?? 'no reason reported'}`,
          detail: 'the baseline promises a measurement this run did not make — install recheck or record the baseline as unmeasured',
          why,
        });
      }
      if (!available) {
        return gate(id, UNMEASURED, {
          expected: b.superLinearRuleIds,
          actual: null,
          detail: `recheck unavailable (${a1.recheckReason ?? 'no reason reported'}); the shape heuristic still gated this run via a1:shape-suspicious-set`,
          why,
        });
      }
      if (b.measured !== true) {
        return gate(id, UNMEASURED, {
          expected: null,
          actual: a1.summary.recheckSuperLinearRuleIds,
          detail: 'recheck is available on this host but the baseline was recorded without it — re-record the baseline to turn this into a real gate',
          why,
        });
      }
      const exp = b.superLinearRuleIds ?? [];
      const act = a1.summary.recheckSuperLinearRuleIds ?? [];
      if (canonicalJson(act) === canonicalJson(exp)) return gate(id, PASS, { expected: exp, actual: act, why });
      const d = diffMultiset(act, exp);
      return gate(id, FAIL, {
        expected: exp,
        actual: act,
        detail: `appeared: ${d.added.join(', ') || '(none)'} | disappeared: ${d.removed.join(', ') || '(none)'}`,
        why,
      });
    });

    // ------------------------------------------- A1, cross-file (0.3.0-β) ----
    // These three close most of MEASURED LIMIT 8. `pushCf` has its own deadness
    // check rather than reusing `push`: the cross-file census runs as a separate
    // child over a separate package, and a failure of the CORE catalogue must not
    // report the cross-file gates as "did not run" — that would hide which half
    // of the rule surface is actually unmeasured.
    const cf = a1?.crossFile ?? null;
    const cfDead = !cf || cf.ran !== true;
    const cfDetail = cfDead
      ? `the cross-file catalogue did not run: ${cf?.run?.spawnError ?? cf?.run?.stderrTail ?? 'unknown reason'}`
      : null;
    const pushCf = (id, fn) => {
      if (!has(id)) {
        produced.push(gate(id, FAIL, { detail: 'no baseline entry for this gate — the baseline is out of date' }));
        return;
      }
      if (cfDead) {
        produced.push(gate(id, FAIL, { detail: cfDetail, why: 'an arm that cannot run is a failure, never a skip' }));
        return;
      }
      produced.push(fn(B[id]));
    };

    pushCf('a1:crossfile-surface-census', (b) => {
      const id = 'a1:crossfile-surface-census';
      const actual = {
        crossFileRules: cf.summary.crossFileRules,
        exportedUnregisteredRuleIds: cf.summary.exportedUnregisteredRuleIds,
        staticFilesScanned: cf.summary.staticFilesScanned,
        staticLiterals: cf.summary.staticLiterals,
        staticConstructionSites: cf.summary.staticConstructionSites,
        staticUncompilable: cf.summary.staticUncompilable,
      };
      const moved = diffRecord(actual, b.expected ?? {});
      const why =
        'the half of the regex attack surface that lives in packages/analysis-graph. Pinned on the STATIC axis ' +
        '(literals + `new RegExp(` sites in the built package) because that is a function of the build alone; ' +
        'the runtime pattern count is a function of the fixture tree and is floored, not pinned.';
      return moved.length === 0
        ? gate(id, PASS, { expected: b.expected, actual, why })
        : gate(id, FAIL, { expected: b.expected, actual, detail: moved.join('; '), why });
    });

    pushCf('a1:crossfile-shape-suspicious-set', (b) => {
      const id = 'a1:crossfile-shape-suspicious-set';
      const exp = b.patterns ?? [];
      const why =
        '§9.4 「新ルールで super-linear が混入したら fail」, extended to the cross-file layer. The set is EMPTY today, ' +
        'and empty is the one value that is stable across both arms: the pattern population of any subset of the ' +
        'fixture tree is a subset of the population measured here, so an empty set on a working tree stays empty on CI. ' +
        '★ An empty expectation cannot tell "examined and clean" from "not examined", so the catalogue also reports a ' +
        'CANARY: three probe strings that must trip exactly their own shape check, plus a benign literal that must trip ' +
        'none. Measured 2026-08-03: stubbing shapeHits() to `return []` left this gate green and the catalogue exit 0. ' +
        'The canary is what makes the empty set mean something.';
      // The canary is checked FIRST. A dead judge reports an empty suspicious
      // set, which would otherwise satisfy the comparison below.
      const canary = cf.summary?.shapeChecker;
      if (!canary || canary.ok !== true) {
        return gate(id, FAIL, {
          expected: { shapeCheckerOk: true, fired: ['adjacent-unbounded', 'nested-quantifier', 'quantified-alternation'] },
          actual: canary ?? null,
          detail: canary
            ? `canary missing: ${(canary.missing ?? []).join(', ') || '(none)'}; benign hits: ${(canary.benignHits ?? []).join(', ') || '(none)'}`
            : 'the catalogue reported no shapeChecker canary at all (stale script or an older catalogue on PATH)',
          why,
        });
      }
      if (canonicalJson(cf.shapeSuspicious) === canonicalJson(exp)) {
        return gate(id, PASS, { expected: exp.length, actual: cf.shapeSuspicious.length, why });
      }
      const d = diffMultiset(cf.shapeSuspicious, exp);
      return gate(id, FAIL, {
        expected: exp,
        actual: cf.shapeSuspicious,
        detail: `appeared: ${d.added.join(', ') || '(none)'} | disappeared: ${d.removed.join(', ') || '(none)'}`,
        why,
      });
    });

    pushCf('a1:crossfile-probe-liveness', (b) => {
      const id = 'a1:crossfile-probe-liveness';
      const why =
        'a census that observed nothing is the strongest possible pass on the weakest possible evidence — this project has ' +
        'already shipped a gate that passed with its fixtures deleted, and an A1 probe that measured 0 patterns and reported PASS. ' +
        'The exact half of this gate is the positive control (four named product regexes, three of them `new RegExp`-built and ' +
        'therefore invisible to any literal scan); the floors exist because the fixture tree is bigger in a working copy than on CI.';
      const exact = {
        positiveControlOk: cf.summary.positiveControlOk,
        positiveControlMissing: cf.summary.positiveControlMissing,
        dynamicRulesWithNoPattern: cf.summary.dynamicRulesWithNoPattern,
        dynamicAnalyzeErrors: cf.summary.dynamicAnalyzeErrors,
      };
      const moved = diffRecord(exact, b.expected ?? {});
      const floors = [
        ['dynamicPatternPairs', b.minDynamicPatternPairs],
        ['dynamicFixtureProjects', b.minFixtureProjects],
        ['crossCheckDynamicNotStatic', b.minRuntimeOnlyPatterns],
      ];
      for (const [key, min] of floors) {
        if (typeof min !== 'number') {
          moved.push(`${key}: the baseline declares no floor for it — an unfloored liveness number governs nothing`);
          continue;
        }
        const v = cf.summary[key];
        if (typeof v !== 'number') moved.push(`${key}: expected a number >= ${min}, got ${JSON.stringify(v)}`);
        else if (v < min) moved.push(`${key}: expected >= ${min}, got ${v}`);
      }
      const actual = {
        ...exact,
        dynamicPatternPairs: cf.summary.dynamicPatternPairs,
        dynamicFixtureProjects: cf.summary.dynamicFixtureProjects,
        crossCheckDynamicNotStatic: cf.summary.crossCheckDynamicNotStatic,
        crossCheckStaticNotDynamic: cf.summary.crossCheckStaticNotDynamic,
      };
      return moved.length === 0
        ? gate(id, PASS, { expected: b.expected, actual, why })
        : gate(id, FAIL, { expected: b.expected, actual, detail: moved.join('; '), why });
    });
  }

  // ----------------------------------------------------------------- B1 ----
  if (armsRun.includes('b1')) {
    const b1 = observed.b1 ?? null;
    const push = (id, fn) => {
      if (!has(id)) {
        produced.push(gate(id, FAIL, { detail: 'no baseline entry for this gate — the baseline is out of date' }));
        return;
      }
      produced.push(fn(B[id]));
    };
    const childFailure = (what) => {
      const g = b1?.gen;
      const e = b1?.evalRun;
      if (g && !g.ok) return `${what}: the B1 corpus generator failed (${g.spawnError ?? g.stderrTail ?? `exit ${g.status}`})`;
      if (e && !e.ok) return `${what}: sec-b1-er-eval.mjs failed (${e.spawnError ?? e.stderrTail ?? `exit ${e.status}`})`;
      return `${what}: the B1 arm produced no observation`;
    };

    push('b1:corpus-scale', (b) => {
      const id = 'b1:corpus-scale';
      const why = 'an empty or shrunken corpus makes ER vacuously 0 — the strongest possible pass on the weakest possible evidence';
      if (!b1?.scale) return gate(id, FAIL, { expected: b.expected, actual: null, detail: childFailure('scale unreadable'), why });
      const moved = diffRecord(b1.scale, b.expected ?? {});
      if (moved.length === 0) return gate(id, PASS, { expected: b.expected, actual: b1.scale, why });
      // MEASURED LIMIT 2 — surface the censuses so an environmental cause is legible.
      const env =
        ` [rejections: ${JSON.stringify(b1.rejectionCensus ?? {})}]` +
        ` [syntax gate: ${JSON.stringify(b1.syntaxCensus ?? {})}]` +
        ' — a large G0-syntax rejection count with tool "python3 -m py_compile" means python3 is missing on this host, not that the generator regressed';
      return gate(id, FAIL, { expected: b.expected, actual: b1.scale, detail: moved.join('; ') + env, why });
    });

    const erGate = (id, key, b) => {
      const why =
        key === 'erTrue'
          ? 'ER on the shipped engine: the fraction of real findings an attacker can rewrite away. Higher is a robustness regression.'
          : 'ER on the pre-D2 control arm: keeps the A/B honest — a control that drifts makes ΔER uninterpretable.';
      if (!b1?.metrics) return gate(id, FAIL, { expected: b.maxEr, actual: null, detail: childFailure('ER unreadable'), why });
      const er = b1.metrics[key];
      const denom = key === 'erTrue' ? b1.metrics.denominatorTrue : b1.metrics.denominatorFalse;
      if (typeof er !== 'number') {
        return gate(id, FAIL, { expected: b.maxEr, actual: er, detail: 'ER is null — the denominator was empty, so nothing was measured', why });
      }
      if (typeof denom !== 'number' || denom < b.minDenominator) {
        return gate(id, FAIL, {
          expected: `denominator >= ${b.minDenominator}`,
          actual: denom,
          detail: 'the ER denominator collapsed; an ER computed over a handful of pairs is not the same measurement',
          why,
        });
      }
      return er <= b.maxEr
        ? gate(id, PASS, { expected: `<= ${b.maxEr} (n >= ${b.minDenominator})`, actual: `${er} (n=${denom})`, why })
        : gate(id, FAIL, { expected: `<= ${b.maxEr}`, actual: er, detail: `evasion rate rose by ${Number((er - b.maxEr).toFixed(6))}`, why });
    };
    push('b1:er-true-ceiling', (b) => erGate('b1:er-true-ceiling', 'erTrue', b));
    push('b1:er-false-ceiling', (b) => erGate('b1:er-false-ceiling', 'erFalse', b));

    push('b1:delta-er-floor', (b) => {
      const id = 'b1:delta-er-floor';
      const why = 'ΔER = ER(pre-D2) − ER(shipped) is how much evasion the D2 canonicalization absorbs; disabling D2 leaves both ERs equal and slips past a ceiling';
      if (!b1?.metrics) return gate(id, FAIL, { expected: `>= ${b.minDeltaEr}`, actual: null, detail: childFailure('ΔER unreadable'), why });
      const d = b1.metrics.deltaEr;
      if (typeof d !== 'number') return gate(id, FAIL, { expected: `>= ${b.minDeltaEr}`, actual: d, detail: 'ΔER is null — one of the two arms had no denominator', why });
      return d >= b.minDeltaEr
        ? gate(id, PASS, { expected: `>= ${b.minDeltaEr}`, actual: d, why })
        : gate(id, FAIL, { expected: `>= ${b.minDeltaEr}`, actual: d, detail: `D2 now covers ${Number((b.minDeltaEr - d).toFixed(6))} less evasion than the baseline`, why });
    });

    push('b1:harness-integrity', (b) => {
      const id = 'b1:harness-integrity';
      const why = 'the evaluator exits 0 even when its own assertions are BROKEN (measured) — so the verdict has to be read out of the JSON';
      if (!b1?.integrity) return gate(id, FAIL, { expected: b.expected, actual: null, detail: childFailure('integrity block unreadable'), why });
      const moved = diffRecord(b1.integrity, b.expected ?? {});
      return moved.length === 0
        ? gate(id, PASS, { expected: b.expected, actual: b1.integrity, why })
        : gate(id, FAIL, { expected: b.expected, actual: b1.integrity, detail: moved.join('; '), why });
    });
  }

  // ----------------------------------------------------------------- B3 ----
  if (armsRun.includes('b3')) {
    const b3 = observed.b3 ?? null;
    const push = (id, fn) => {
      if (!has(id)) {
        produced.push(gate(id, FAIL, { detail: 'no baseline entry for this gate — the baseline is out of date' }));
        return;
      }
      produced.push(fn(B[id]));
    };
    const childFailure = (what) => {
      const g = b3?.gen;
      const e = b3?.evalRun;
      if (g && !g.ok) return `${what}: the B3 corpus generator failed (${g.spawnError ?? g.stderrTail ?? `exit ${g.status}`})`;
      if (e && !e.ok) return `${what}: sec-b3-cr-eval.mjs failed (${e.spawnError ?? e.stderrTail ?? `exit ${e.status}`})`;
      return `${what}: the B3 arm produced no observation`;
    };

    push('b3:corpus-scale', (b) => {
      const id = 'b3:corpus-scale';
      const why = 'same vacuous-pass hazard as B1: an empty disguise corpus makes CR 0 and the gate green';
      if (!b3?.scale) return gate(id, FAIL, { expected: b.expected, actual: null, detail: childFailure('scale unreadable'), why });
      const moved = diffRecord(b3.scale, b.expected ?? {});
      return moved.length === 0
        ? gate(id, PASS, { expected: b.expected, actual: b3.scale, why })
        : gate(id, FAIL, { expected: b.expected, actual: b3.scale, detail: moved.join('; '), why });
    });

    push('b3:cr-gated-ceiling', (b) => {
      const id = 'b3:cr-gated-ceiling';
      const why = 'CR after D1: how much of a real finding an attacker can hide from confidence-based triage. Higher is a regression.';
      if (!b3?.metrics) return gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: null, detail: childFailure('CR unreadable'), why });
      const m = b3.metrics;
      if (m.threshold !== b.threshold) {
        return gate(id, FAIL, { expected: `threshold ${b.threshold}`, actual: `threshold ${m.threshold}`, detail: 'the CR was computed at a different confidence threshold than the baseline — the numbers are not comparable', why });
      }
      if (m.worstCaseRow !== b.worstCaseRow) {
        return gate(id, FAIL, {
          expected: `worst-case row ${b.worstCaseRow}`,
          actual: `worst-case row ${m.worstCaseRow}`,
          detail: 'the worst case moved to a different (transform, severity) row — the threshold below would be comparing two different attacks',
          why,
        });
      }
      if (typeof m.worstCaseDenominator !== 'number' || m.worstCaseDenominator < b.minDenominator) {
        return gate(id, FAIL, { expected: `denominator >= ${b.minDenominator}`, actual: m.worstCaseDenominator, detail: 'the worst-case denominator collapsed', why });
      }
      if (typeof m.worstCaseCrGated !== 'number') {
        return gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: m.worstCaseCrGated, detail: 'gated CR is null — nothing was measured', why });
      }
      return m.worstCaseCrGated <= b.maxCrGated
        ? gate(id, PASS, { expected: `<= ${b.maxCrGated} at ${b.worstCaseRow}`, actual: `${m.worstCaseCrGated} (n=${m.worstCaseDenominator})`, why })
        : gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: m.worstCaseCrGated, detail: 'concealment got easier', why });
    });

    push('b3:d1-reduction-floor', (b) => {
      const id = 'b3:d1-reduction-floor';
      const why =
        'D1 (the severity floor) is what drives the gated CR to 0. Removing it does not push CR above a ceiling it was already under — ' +
        'it collapses the REDUCTION, so the reduction is the quantity with a genuine lower bound.';
      if (!b3?.metrics) return gate(id, FAIL, { expected: `>= ${b.minReduction}`, actual: null, detail: childFailure('reduction unreadable'), why });
      const m = b3.metrics;
      if (typeof m.worstCaseCrUngated !== 'number' || typeof m.worstCaseCrGated !== 'number') {
        return gate(id, FAIL, { expected: `>= ${b.minReduction}`, actual: null, detail: 'one of the two arms is null — the reduction is undefined, not zero', why });
      }
      const reduction = Number((m.worstCaseCrUngated - m.worstCaseCrGated).toFixed(6));
      return reduction >= b.minReduction
        ? gate(id, PASS, { expected: `>= ${b.minReduction}`, actual: reduction, why })
        : gate(id, FAIL, { expected: `>= ${b.minReduction}`, actual: reduction, detail: `D1 now removes ${Number((b.minReduction - reduction).toFixed(6))} less concealment than the baseline`, why });
    });

    push('b3:undeclared-cr-ceiling', (b) => {
      const id = 'b3:undeclared-cr-ceiling';
      const why = 'the declared defence target: a disguise the attacker never declares must be worth nothing after D1 (declared suppression is a legitimate feature and is NOT gated to 0)';
      if (!b3?.metrics) return gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: null, detail: childFailure('disclosure split unreadable'), why });
      const m = b3.metrics;
      if (typeof m.undeclaredDenominator !== 'number' || m.undeclaredDenominator < b.minDenominator) {
        return gate(id, FAIL, { expected: `denominator >= ${b.minDenominator}`, actual: m.undeclaredDenominator, detail: 'the undeclared-disguise denominator collapsed', why });
      }
      if (typeof m.undeclaredCrGated !== 'number') {
        return gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: m.undeclaredCrGated, detail: 'undeclared gated CR is null — nothing was measured', why });
      }
      return m.undeclaredCrGated <= b.maxCrGated
        ? gate(id, PASS, { expected: `<= ${b.maxCrGated}`, actual: `${m.undeclaredCrGated} (n=${m.undeclaredDenominator})`, why })
        : gate(id, FAIL, { expected: `<= ${b.maxCrGated}`, actual: m.undeclaredCrGated, detail: 'an undeclared disguise now conceals findings from triage', why });
    });

    push('b3:harness-integrity', (b) => {
      const id = 'b3:harness-integrity';
      const why = 'same reason as B1: the evaluator reports its own breakage in the JSON and still exits 0';
      if (!b3?.integrity) return gate(id, FAIL, { expected: b.expected, actual: null, detail: childFailure('integrity block unreadable'), why });
      const exp = { ...(b.expected ?? {}) };
      const minAgreement = exp.minPairingAgreement;
      delete exp.minPairingAgreement;
      const actual = { ...b3.integrity };
      const agreement = actual.pairingAgreement;
      delete actual.pairingAgreement;
      const moved = diffRecord(actual, exp);
      if (typeof minAgreement === 'number') {
        if (typeof agreement !== 'number') moved.push(`pairingAgreement: expected a number >= ${minAgreement}, got ${JSON.stringify(agreement)}`);
        else if (agreement < minAgreement) moved.push(`pairingAgreement: expected >= ${minAgreement}, got ${agreement}`);
      }
      return moved.length === 0
        ? gate(id, PASS, { expected: b.expected, actual: b3.integrity, why })
        : gate(id, FAIL, { expected: b.expected, actual: b3.integrity, detail: moved.join('; '), why });
    });
  }

  // ------------------------------------------------- completeness & tally --
  // A gate the baseline declares for an arm that RAN but which produced no
  // verdict means a check was removed while the build stayed green. That is the
  // failure mode a self-hardening gate is least able to notice about itself, so
  // it is checked explicitly rather than assumed away.
  const producedIds = new Set(produced.map((g) => g.id));
  const missing = Object.keys(B)
    .filter((id) => armsRun.includes(String(id).split(':')[0]))
    .filter((id) => !producedIds.has(id))
    .sort();
  for (const id of missing) {
    produced.push(
      gate(id, FAIL, {
        detail: 'the baseline declares this gate and its arm ran, but the harness produced no verdict for it (a check was removed)',
        why: 'silent removal of a gate is indistinguishable from a green build unless it is checked',
      }),
    );
  }

  produced.sort((a, b) => a.id.localeCompare(b.id));

  const optional = new Set(baseline.optionalGates ?? []);
  const failed = produced.filter((g) => g.verdict === FAIL);
  const unmeasured = produced.filter((g) => g.verdict === UNMEASURED);
  // An unmeasured gate is NEVER a pass. It is tolerated (exit 0) only when the
  // baseline pre-declares it optional — which is a decision recorded in git, not
  // one this script makes at runtime.
  const unmeasuredNotAllowed = unmeasured.filter((g) => !optional.has(g.id));

  return {
    gates: produced,
    summary: {
      total: produced.length,
      passed: produced.filter((g) => g.verdict === PASS).length,
      failed: failed.length,
      unmeasured: unmeasured.length,
      unmeasuredNotAllowed: unmeasuredNotAllowed.length,
      failedGateIds: failed.map((g) => g.id),
      unmeasuredGateIds: unmeasured.map((g) => g.id),
      // Deliberately NOT `failed === 0`: a run with unmeasured gates has not
      // demonstrated what the baseline claims it demonstrates.
      allGatesPassed: failed.length === 0 && unmeasured.length === 0,
      ok: failed.length === 0 && unmeasuredNotAllowed.length === 0,
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(argv) {
  const args = parseArgs(argv);
  if (args.unknownArms.length > 0) {
    console.error(`sec-selftest: unknown arm(s) ${args.unknownArms.join(', ')} (known: ${ARMS.join(', ')})`);
    return 2;
  }
  if (args.arms.length === 0) {
    console.error('sec-selftest: --arms selected nothing to run; a gate that runs nothing must not report a pass.');
    return 2;
  }

  let baseline;
  try {
    baseline = loadBaseline(args.baselinePath);
  } catch (err) {
    console.error(`\nsec-selftest: ${err.message}\n`);
    return 1;
  }

  // ---- observe --------------------------------------------------------------
  const raw = {};
  if (args.arms.includes('corpus')) raw.corpus = await runCorpusArm();
  if (args.arms.includes('a1')) raw.a1 = runA1Arm();
  if (args.arms.includes('b1')) raw.b1 = runB1Arm(args.b1Manifest);
  if (args.arms.includes('b3')) raw.b3 = runB3Arm(args.b3Manifest);

  // ---- the GATED object: deterministic, no clock, no host, no paths ---------
  // Everything a gate reads and nothing else. Two runs of this script on the
  // same tree produce an identical `observed` and therefore an identical
  // `observedDigest`; that equality is the determinism check.
  const observed = {
    arms: [...args.arms].sort(),
    corpus: raw.corpus
      ? Object.fromEntries(
          CORPUS_DIRS.map((d) => [
            d,
            {
              present: raw.corpus[d].present,
              count: raw.corpus[d].count,
              files: raw.corpus[d].files,
              findings: raw.corpus[d].findings,
            },
          ]),
        )
      : null,
    a1: raw.a1
      ? {
          ran: raw.a1.ran,
          summary: raw.a1.summary,
          shapeSuspicious: raw.a1.shapeSuspicious,
          unreachedRuleIds: raw.a1.unreachedRuleIds,
          // `fixtureRoot` and every path the cross-file census reports are
          // deliberately NOT here: the digest must not move because someone
          // pointed `--fixtures` somewhere else. Only the counts and the verdicts.
          crossFile: raw.a1.crossFile
            ? { ran: raw.a1.crossFile.ran, summary: raw.a1.crossFile.summary, shapeSuspicious: raw.a1.crossFile.shapeSuspicious }
            : null,
        }
      : null,
    b1: raw.b1 ? { scale: raw.b1.scale, metrics: raw.b1.metrics, integrity: raw.b1.integrity } : null,
    b3: raw.b3 ? { scale: raw.b3.scale, metrics: raw.b3.metrics, integrity: raw.b3.integrity } : null,
  };
  const observedDigest = digestOf(observed);

  // The gate reads the RAW arms (they carry the child-process failure detail the
  // gated object deliberately omits), but every threshold comparison is over the
  // same numbers `observed` holds.
  const result = evaluateGates(raw, baseline, args.arms);

  // ---- record ---------------------------------------------------------------
  const complete = args.arms.length === ARMS.length && !args.b1Manifest && !args.b3Manifest;
  const record = {
    generatedBy: 'sec-selftest.mjs',
    purpose:
      'H2 self-hardening CI. The GATE authority is the tracked ' +
      'scripts/sec-selftest-baseline.json; this file is a local report and is never read back as an expectation.',
    baseline: slash(args.baselinePath),
    baselineRecordedAt: baseline.recordedAt ?? null,
    // false when arms were filtered or a manifest was reused: the run did not
    // exercise the full contract and must not be quoted as if it had.
    authoritative: complete,
    authoritativeNote: complete
      ? null
      : `partial run (arms: ${args.arms.join(',')}${args.b1Manifest ? ', b1 manifest reused' : ''}${args.b3Manifest ? ', b3 manifest reused' : ''})`,
    observedDigest,
    observed,
    verdict: result.summary,
    gates: result.gates,
    // Everything below is NON-DETERMINISTIC by nature and is deliberately kept
    // out of `observed` so the digest stays stable across runs and hosts.
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      childRuns: [raw.a1?.run, raw.a1?.crossFile?.run, raw.b1?.gen, raw.b1?.evalRun, raw.b3?.gen, raw.b3?.evalRun]
        .filter(Boolean)
        .map((r) => ({ script: r.script, status: r.status, ok: r.ok, spawnError: r.spawnError })),
      b1SyntaxGateCensus: raw.b1?.syntaxCensus ?? null,
      b1RejectionCensus: raw.b1?.rejectionCensus ?? null,
      // Host-specific (it embeds an absolute module path), which is exactly why
      // it lives here and not in `observed`.
      a1RecheckReason: raw.a1?.recheckReason ?? null,
    },
  };
  mkdirSync(dirname(resolve(REPO_ROOT, args.manifestOut)), { recursive: true });
  writeFileSync(resolve(REPO_ROOT, args.manifestOut), `${JSON.stringify(record, null, 2)}\n`, 'utf8');

  // ---- report ---------------------------------------------------------------
  const mark = { [PASS]: 'PASS', [FAIL]: 'FAIL', [UNMEASURED]: 'UNMEASURED' };
  console.log('# H2 — self-hardening CI selftest\n');
  console.log(`baseline: ${slash(args.baselinePath)}  ·  arms: ${args.arms.join(', ')}  ·  authoritative: ${complete}`);
  console.log(`observed digest: ${observedDigest}\n`);
  // `show` is the only path a gate's numbers take to stdout. Routing every one
  // of them through one function is deliberate: a future line that prints a
  // reading some other way would bypass the redaction, and the test asserts
  // against the whole rendered report rather than against this function, so
  // that bypass fails the suite instead of shipping.
  const show = (g, v) => (args.redactMetrics && isRedactedGate(g.id) ? REDACTED : typeof v === 'object' ? canonicalJson(v) : v);
  for (const g of result.gates) {
    console.log(`${mark[g.verdict].padEnd(11)} ${g.id}`);
    if (g.verdict === PASS) {
      if (g.actual != null) console.log(`            ${show(g, g.actual)}`);
      continue;
    }
    console.log(`            expected: ${show(g, g.expected)}`);
    console.log(`            actual:   ${show(g, g.actual)}`);
    // `detail` is prose built from the measurement ("evasion rate rose by X"),
    // so it carries the reading even when `actual` has been withheld. `why` is
    // a static explanation of the gate and stays: it is the part a reader of a
    // red public run actually needs.
    if (g.detail) console.log(`            ${show(g, g.detail)}`);
    if (g.why) console.log(`            why it is gated: ${g.why}`);
  }
  const s = result.summary;
  console.log(
    `\n${s.passed}/${s.total} gates passed · ${s.failed} failed · ${s.unmeasured} unmeasured ` +
      `(${s.unmeasuredNotAllowed} of them not pre-declared optional)`,
  );
  if (s.failed > 0) console.log(`FAILED GATES: ${s.failedGateIds.join(', ')}`);
  if (s.unmeasured > 0) console.log(`UNMEASURED (not counted as passes): ${s.unmeasuredGateIds.join(', ')}`);
  // The manifest path names the withheld directory, so on a public surface it
  // is the same class of disclosure as the readings. The file is still written
  // — only the announcement of where is withheld.
  console.log(args.redactMetrics ? 'wrote the run manifest (path withheld)' : `wrote ${slash(args.manifestOut)}`);

  return s.ok ? 0 : 1;
}

// Executed as a program vs imported by the test: the test needs `evaluateGates`
// and `loadBaseline` as pure functions, and importing a module that runs the
// whole 30 s pipeline on import would make that impossible.
const invokedDirectly =
  process.argv[1] != null && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  process.exitCode = await main(process.argv.slice(2));
}

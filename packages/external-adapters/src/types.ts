// The contract between the report adapters and the ensemble merger.
//
// ★★ WHY THIS PACKAGE PARSES REPORTS AND DOES NOT RUN TOOLS
//
// The obvious shape for "multi-tool ensemble" is a runner: shell out to
// `semgrep --json`, shell out to `codeql database analyze`, merge. That shape is
// refused here, and the refusal is the load-bearing design decision of the whole
// package rather than a limitation to be apologised for.
//
//  - NEITHER TOOL EXISTS ON THE MACHINE THIS WAS WRITTEN ON. Verified with
//    `which`: no `semgrep`, no `codeql`. An invocation path written under those
//    conditions is code that has never once been executed being shipped in a
//    product — the argv it builds, the exit codes it tolerates, the stdout
//    buffering it assumes, all of it unfalsified. This repository already refuses
//    that class of claim everywhere else (see the SCAFFOLDED-AND-BLOCKED header of
//    scripts/sec-transfer-codeql.mjs, which delivers runnable code and openly
//    reports `blocked` rather than inventing a column of numbers). Shipping an
//    untested spawn to end users would be a strictly worse version of the same
//    mistake, because a research script that fails loudly is recoverable and a
//    product feature that fails quietly is not.
//  - IT WOULD CHANGE THE ZERO-EGRESS AUDIT SURFACE. Semgrep phones home by
//    default (its `--metrics` channel; scripts/sec-transfer-semgrep.mjs has to
//    pass `--metrics=off` explicitly to stop it). "VibeGuard makes no network
//    calls" is currently a property of VibeGuard's own code and is auditable by
//    reading it. The moment VibeGuard spawns a process that does make network
//    calls, the property becomes "VibeGuard makes no network calls, except
//    transitively, depending on flags" — a claim a reader can no longer check by
//    reading this repository. Parsing a file the user already has costs nothing
//    on that axis: nothing in this package opens a socket, and nothing in it
//    opens a process either. There is no `node:child_process` import anywhere
//    under src/, and that absence is asserted by a test.
//
// So v1 is a REPORT-INGESTION CONTRACT. The user runs whichever tools they run,
// however they run them (locally, in CI, in a container), and hands the resulting
// report files to VibeGuard:
//
//   vibeguard scan . --ensemble \
//     --semgrep-report semgrep.json \
//     --codeql-report codeql.sarif
//
// Invocation is future work and is named as such in README.md. It is not
// scaffolded here, because a scaffold is the thing that gets mistaken for a
// feature.
//
// ★★ AND WHY "NO REPORT SUPPLIED" IS A FIRST-CLASS STATE
//
// The failure this package is most likely to cause, if built carelessly, is a
// lie of omission. `--ensemble` with no `--semgrep-report` produces an empty
// external finding set; so does `--ensemble --semgrep-report clean.json` where
// Semgrep genuinely found nothing. Those two are the same bytes downstream and
// they are opposite facts:
//
//   "Semgrep found nothing here"   — evidence. Two engines looked and agreed.
//   "Semgrep was never run"        — no evidence at all.
//
// A merger that renders them identically tells the reader the first when the
// truth is the second, and it does so at exactly the moment the reader is
// deciding whether the code is safe. So participation is modelled explicitly, as
// a three-state per tool (`ToolSide`), it survives into the result
// (`ToolParticipation`), and every conclusion the merger draws is gated on it —
// see `EnsembleResult.agreementComputable`.

import type { Confidence, Finding, Severity } from '@vibeguard/findings-schema';
import type { WeaknessClass } from './weakness-class.js';

/**
 * A tool whose report this package can ingest.
 *
 * Deliberately NOT extensible by string: adding a tool means adding an adapter,
 * a weakness-class mapping for its rule ids, and a fixture, and a `string` type
 * would let a caller register a tool for which none of those exist. The merger
 * would then happily report `unanimous` over a tool that has no detectors mapped
 * at all, which is the single most misleading output this package could produce.
 */
export type ExternalToolId = 'semgrep' | 'codeql';

/** Every participant in an ensemble, VibeGuard's own engine included. */
export type EnsembleToolId = 'vibeguard' | ExternalToolId;

/** Stable display order. Used for every sorted output so runs are comparable. */
export const ENSEMBLE_TOOL_ORDER: readonly EnsembleToolId[] = ['vibeguard', 'semgrep', 'codeql'];

/**
 * How a set of findings came to be in this process.
 *
 * ★ THERE IS NO VALUE HERE THAT MEANS "VIBEGUARD RAN THE EXTERNAL TOOL", AND
 * THERE MUST NEVER BE ONE. The union is closed at two members precisely so that
 * adding such a claim requires editing this line, in a file whose header explains
 * why the claim would be false. A string field would have let a future call site
 * write `obtainedBy: 'executed'` and nothing would have caught it.
 *
 *  - `user-supplied-report` — parsed out of a file the user obtained elsewhere.
 *    This package did not run the tool, does not know how it was invoked, does
 *    not know which ruleset it used beyond what the report says, and does not
 *    know when it was produced beyond what the report says.
 *  - `vibeguard-in-process` — produced by VibeGuard's own engine in this process.
 *    The only findings about which this package can make an execution claim.
 */
export type ProvenanceKind = 'user-supplied-report' | 'vibeguard-in-process';

/**
 * Where one finding came from, carried on the finding itself.
 *
 * Every field is a fact the report (or the process) actually stated. Nothing here
 * is inferred, and the fields that can be unknown are typed `| null` rather than
 * given a plausible default — `versionFromReport: null` reads as "the report did
 * not say", which is the truth, while `versionFromReport: 'unknown'` reads as a
 * version string and will end up quoted as one.
 */
export interface ToolProvenance {
  tool: EnsembleToolId;
  /**
   * The tool version AS WRITTEN IN THE REPORT — Semgrep's top-level `version`,
   * CodeQL's `runs[].tool.driver.semanticVersion` (falling back to `version`).
   * `null` when the report carried no version. Never guessed, never taken from
   * anything but the report itself.
   */
  versionFromReport: string | null;
  /**
   * The path the caller said this report came from. Recorded verbatim for the
   * audit trail; this package never opens it. `null` for the in-process
   * VibeGuard side, which has no report file.
   */
  reportPath: string | null;
  obtainedBy: ProvenanceKind;
}

/**
 * An external tool's finding, normalised onto the project's `Finding` shape.
 *
 * ★ EXTENDS `Finding` RATHER THAN SITTING BESIDE IT, for exactly the reason
 * `DesignSmellFinding` does (see its header in @vibeguard/findings-schema):
 * every consumer downstream — the SARIF adapter, the CLI formatters, `--fail-on`,
 * suppression, the summary counts — operates on `Finding`, and a parallel shape
 * would mean a second pipeline, i.e. a second product. The inherited flat fields
 * stay populated and stay authoritative for anything that only knows `Finding`;
 * everything added here is strictly extra for consumers that know to look.
 *
 * `sourceEngine` is set from the schema's existing union: `'semgrep'` for
 * Semgrep, `'external'` for CodeQL. That union predates this package and is not
 * widened by it — `SourceEngine` already had a slot for exactly this.
 */
export interface ExternalFinding extends Finding {
  provenance: ToolProvenance;
  /**
   * The weakness family this finding was mapped to, or `null` when the tool's
   * rule id matched nothing in the mapping table.
   *
   * `null` is NOT "no weakness". It is "this package cannot say which weakness",
   * and the merger treats it as a hard stop rather than as a mismatch — see
   * `Agreement.unclassified`.
   */
  weaknessClass: WeaknessClass | null;
  /** The tool's own check identifier, verbatim: Semgrep `check_id`, CodeQL rule id. */
  toolRuleId: string;
  /**
   * The severity string the tool used, verbatim (`ERROR`, `warning`, …), kept
   * beside the mapped `severity` so a reader can see what was mapped from what
   * and disagree with the mapping without re-reading the report.
   */
  rawSeverity: string | null;
  /** CWE identifiers the report attached, normalised to `CWE-<n>`. Possibly empty. */
  cweIds: string[];
}

/**
 * What a report parse produced, including what it refused.
 *
 * `refused` exists because the alternative — dropping unusable results silently —
 * is the same class of defect as the participation problem above. A report with
 * 40 results of which 12 had no locatable region is a different fact from a
 * report with 28 results, and only one of those two facts is true.
 */
export interface ExternalReport {
  tool: ExternalToolId;
  provenance: ToolProvenance;
  findings: ExternalFinding[];
  /**
   * Results present in the report that this package would not place. Each entry
   * says which result (by index in the report) and why. Currently the only cause
   * is a result with no resolvable start line — see `RefusedResult`.
   */
  refused: RefusedResult[];
  /**
   * Errors the TOOL ITSELF reported (Semgrep's `errors[]`). A scan with parse
   * errors saw less than the whole input, and a merger that treats its silence
   * as coverage is wrong in the direction that flatters the result.
   */
  toolReportedErrors: string[];
  /**
   * Files the tool says it scanned, normalised. Empty when the report format
   * does not carry the information (SARIF has no equivalent of Semgrep's
   * `paths.scanned` that CodeQL reliably populates). Empty therefore means
   * UNKNOWN COVERAGE, not "scanned nothing".
   */
  scannedPaths: string[];
}

/** One result the adapter would not turn into a finding, and why. */
export interface RefusedResult {
  /** 0-based index of the result in the report's own results array. */
  index: number;
  toolRuleId: string;
  reason: string;
}

/**
 * Per-tool participation in one ensemble run — the three-state from the header.
 *
 * A tagged union rather than an optional field. `semgrep?: ExternalReport` would
 * make "not supplied" the value a caller produces by forgetting the key, and the
 * whole point is that not-supplied must be STATED. Every member of
 * `EnsembleInput` is required, so a caller that adds a tool to the ensemble
 * cannot fail to say what happened to it.
 */
export type ToolSide<R> =
  | { kind: 'not-supplied' }
  | { kind: 'unreadable'; reportPath: string; reason: string }
  | { kind: 'report'; report: R };

/** `{ kind: 'not-supplied' }`, named so call sites read as declarations. */
export function notSupplied<R>(): ToolSide<R> {
  return { kind: 'not-supplied' };
}

/**
 * The report file existed but could not be turned into findings.
 *
 * Kept distinct from `not-supplied` because the user's intent differs and so
 * does the right thing to print: `not-supplied` is "you did not ask for
 * Semgrep", `unreadable` is "you asked for Semgrep and I could not read what
 * you gave me", which is a request that FAILED and should be visible as one.
 * Both are equally not-evidence, and the merger treats them identically when
 * deciding participation — the distinction is for the human.
 */
export function unreadableReport<R>(reportPath: string, reason: string): ToolSide<R> {
  return { kind: 'unreadable', reportPath, reason };
}

/** A parsed report, wrapped for `EnsembleInput`. */
export function suppliedReport<R>(report: R): ToolSide<R> {
  return { kind: 'report', report };
}

/**
 * A parse failure. Thrown by the adapters rather than returned, so that the
 * happy path stays a plain `ExternalReport` and a caller cannot accidentally
 * treat a failure as an empty report — which is the same conflation the whole
 * participation model exists to prevent, one layer down.
 */
export class ExternalReportError extends Error {
  readonly tool: ExternalToolId;
  readonly reportPath: string | null;

  constructor(tool: ExternalToolId, reportPath: string | null, message: string) {
    super(message);
    this.name = 'ExternalReportError';
    this.tool = tool;
    this.reportPath = reportPath;
  }
}

/** Options every adapter accepts. */
export interface AdapterOptions {
  /**
   * The path the report was read from. Recorded in provenance; never opened.
   * Required, and required to be a string rather than optional, because a
   * provenance record whose `reportPath` is missing cannot be audited back to a
   * file and is therefore worth less than no record at all.
   */
  reportPath: string;
  /**
   * When set, absolute paths in the report are reduced to paths relative to this
   * directory, matching what `scripts/sec-transfer-semgrep.mjs` does with
   * `relative(REPO_ROOT, resolve(REPO_ROOT, p))`.
   *
   * ★ OFF BY DEFAULT, AND THAT DEFAULT IS THE DIVERGENCE-CONTROL DECISION.
   * The two existing in-repo parsers already disagree here:
   * `sec-transfer-semgrep.mjs` reduces every path against `process.cwd()`, while
   * `sast-baseline-eval.mjs` only swaps backslashes for slashes. On the relative
   * paths both were written for, the two agree exactly (proved in
   * parser-parity.test.ts); on an absolute path they produce different strings.
   * Neither behaviour is right for a report the USER supplies, because this
   * package does not know which directory the user ran the tool from — so the
   * default is to normalise separators and nothing else, and repo-rooting is an
   * explicit opt-in the caller takes responsibility for.
   */
  rootDir?: string;
}

/**
 * How much the tools that could have spoken actually agreed about one weakness at
 * one place.
 *
 * ★ THE RESEARCH CLAIM THIS ENCODES, AND THE TWO WAYS IT COULD BE FAKED.
 *
 * The claim: a finding only one tool reports needs investigation; a weakness all
 * tools miss is the highest risk. Turning that into a label runs into two traps,
 * and the extra members of this union exist entirely to avoid them.
 *
 * TRAP 1 — silence from a tool that has no detector. Semgrep's p/default fires
 * `go.lang.security.audit.crypto.math_random.math-random-used`; VibeGuard has no
 * rule for weak PRNGs in Go. Labelling that `unique-to-semgrep` invites the
 * reading "VibeGuard missed it", when in fact VibeGuard never looks. That is not
 * a miss, it is a coverage gap, and conflating the two overstates the ensemble's
 * value in the direction that flatters this project. `sole-detector` is the
 * honest label: exactly one participating tool has a detector for this class, so
 * everyone else's silence carries no information.
 *
 * TRAP 2 — silence about a weakness nobody could name. Most findings, from every
 * tool, map to no weakness class at all: the mapping tables cover 9 families, and
 * the real Semgrep fixture in this package contains `csrf-exempt`,
 * `express-session-hardcoded-secret`, `express-cookie-session-no-domain` and
 * `math-random-used`, none of which any table maps. Two unmapped findings at the
 * same line from two tools MIGHT be the same weakness; this package cannot tell,
 * so it must not say. `unclassified` is that refusal, and it is deliberately not
 * a synonym for `unique-to-tool`.
 *
 * WHAT IS DELIBERATELY ABSENT: a member for "no tool found it". It cannot exist.
 * A merger sees only what was reported; a weakness every tool missed produces no
 * row in any report and therefore no row here. The research claim that such
 * weaknesses are the highest risk is TRUE and is exactly the thing this artifact
 * cannot measure, so `EnsembleResult.unobservable` states it in prose in the
 * output rather than letting an empty bucket imply the count is zero.
 */
export type Agreement =
  /** Every participating tool that has a detector for this class reported it. Requires ≥2 such tools. */
  | 'unanimous'
  /** ≥2 tools reported it, but at least one tool with a detector did not. */
  | 'corroborated'
  /** Exactly 1 tool reported it, and ≥1 other participating tool has a detector for the class and stayed silent. */
  | 'unique-to-tool'
  /** Exactly 1 participating tool has a detector for this class at all. Nobody else's silence means anything. */
  | 'sole-detector'
  /** No weakness class could be derived, so the question cannot be asked. */
  | 'unclassified'
  /** Fewer than two tools participated. Agreement is not defined over one tool. */
  | 'not-computable';

/** Every agreement label, in decreasing order of how much corroboration it represents. */
export const AGREEMENT_ORDER: readonly Agreement[] = [
  'unanimous',
  'corroborated',
  'unique-to-tool',
  'sole-detector',
  'unclassified',
  'not-computable',
];

/** One tool's contribution to a merged finding. */
export interface EnsembleMember {
  tool: EnsembleToolId;
  /** The rule id in that tool's own vocabulary (`VG-INJ-001`, `py/sql-injection`, …). */
  toolRuleId: string;
  severity: Severity;
  confidence: Confidence;
  filePath: string;
  startLine: number;
  message: string;
  provenance: ToolProvenance;
}

/**
 * One weakness, at one place, as seen by everyone who saw it.
 *
 * `filePath`/`startLine` are the CLUSTER ANCHOR — the lowest-line member — not an
 * average or a range. An average would name a line no tool reported, which is the
 * one line a reader must not be sent to.
 */
export interface MergedFinding {
  weaknessClass: WeaknessClass | null;
  filePath: string;
  startLine: number;
  agreement: Agreement;
  /** Tools that reported this weakness here, in `ENSEMBLE_TOOL_ORDER`. */
  reportedBy: EnsembleToolId[];
  /**
   * Participating tools that ship a detector for this weakness class, per the
   * mapping tables. Empty when the class is `null` — an unmapped finding has no
   * known set of tools that could have found it.
   */
  couldHaveBeenReportedBy: EnsembleToolId[];
  /**
   * `couldHaveBeenReportedBy` minus `reportedBy`: tools that were looking for
   * this class of weakness and did not report one here. THE interesting field
   * for the research claim, and the one a reader should be pointed at.
   */
  silentTools: EnsembleToolId[];
  members: EnsembleMember[];
}

/**
 * What happened to one tool in one ensemble run, as it appears in the output.
 *
 * ★ EVERY COUNT IS `number | null`, AND `null` IS NOT ZERO. A tool that did not
 * participate contributed no findings and also refused no results; writing `0`
 * for both would render identically to a tool that participated and found
 * nothing, which is the exact conflation this whole package exists to prevent.
 * `null` forces a renderer to print something other than a number.
 */
export interface ToolParticipation {
  tool: EnsembleToolId;
  status: 'participated' | 'not-supplied' | 'report-unreadable';
  /** Human-readable, and written to be printable verbatim. Never empty. */
  detail: string;
  provenance: ToolProvenance | null;
  /** Findings this tool contributed to the merge. `null` when it did not participate. */
  findingCount: number | null;
  /**
   * Findings the tool reported that were NOT merged because they could not be
   * located (no line, or no path). `null` when the tool did not participate.
   * A large number here means the merge saw much less than the report contains.
   */
  refusedCount: number | null;
  /**
   * Problems the TOOL reported about its own run — Semgrep `errors[]`, SARIF
   * `toolExecutionNotifications`. A run with these analysed less than it appears
   * to have, so its silence is worth less than a clean run's.
   */
  toolReportedErrors: string[];
}

/** Everything a merged ensemble run knows, including what it does not know. */
export interface EnsembleResult {
  /** One entry per member of `ENSEMBLE_TOOL_ORDER`, always all three. */
  participation: ToolParticipation[];
  participatingTools: EnsembleToolId[];
  /**
   * True when fewer than all three tools participated. The CLI must print
   * `degradedNotice` when this is set; a run that silently drops to one tool is
   * the failure mode this package was built to prevent.
   */
  degraded: boolean;
  /** Printable sentence naming exactly which tools are absent and why. `null` when nothing is. */
  degradedNotice: string | null;
  /** False when fewer than two tools participated. Every `agreement` is then `not-computable`. */
  agreementComputable: boolean;
  agreementNotComputableReason: string | null;
  merged: MergedFinding[];
  /** Counts per label. Every label present, including zeros — a missing key would read as "not measured". */
  byAgreement: Record<Agreement, number>;
  mappingCoverage: MappingCoverage;
  /**
   * The standing caveat about what this artifact cannot see. Emitted as prose,
   * in the output, every time — see the note on `Agreement`.
   */
  unobservable: string;
  /** Line tolerance used when clustering. Recorded so a reader can reproduce the clustering. */
  lineTolerance: number;
}

/** How much of what was merged the weakness mapping could actually name. */
export interface MappingCoverage {
  totalFindings: number;
  classified: number;
  unclassified: number;
  /** Per-tool `{ classified, unclassified }`, so a lopsided mapping is visible. */
  byTool: Record<string, { classified: number; unclassified: number }>;
  /**
   * Rule ids that matched no family, deduplicated and sorted. This is the
   * to-do list for extending the mapping, and printing it is what stops
   * "unclassified" from being a silent bucket.
   */
  unmappedRuleIds: string[];
}

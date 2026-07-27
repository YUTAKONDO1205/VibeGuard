export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type SourceEngine = 'core-rule' | 'semgrep' | 'external';
export type ScanMode = 'fast' | 'standard' | 'deep';
export type TargetType = 'file' | 'snippet' | 'diff' | 'repo';

export interface Remediation {
  why: string;
  how: string;
  exampleFix?: string;
  references?: string[];
}

/** A reason the context layer lowered (or tried to lower) a match's confidence. */
export type DowngradeSignal = 'comment' | 'docstring' | 'test-path';

/**
 * Why a finding ended up with the confidence it has, when the surrounding
 * context argued for something lower.
 *
 * The field that carries the weight is `floored`. Read naively, the interesting
 * audit event would be "a finding was downgraded" — but the severity gate
 * (`SEVERITY_CONFIDENCE_FLOOR`) means a critical/high finding is *never*
 * downgraded, so a `downgraded` flag would be dead on arrival for exactly the
 * findings worth auditing. The observable event is the inverse: the context
 * signals asked for a downgrade and the gate refused. That is what someone
 * wrapping a real vulnerability in a comment or a `tests/` path looks like from
 * the inside, so `floored: true` marks an attempted-and-neutralised hiding
 * attempt rather than a mere scoring detail.
 *
 * Present only when at least one signal fired, so a clean finding carries no
 * extra bytes and the key's presence is itself the "context argued about this
 * one" bit. Absent entirely for findings whose rule supplied a per-match
 * confidence: those bypass the context layer, and inventing an audit trail for
 * an evaluation that never ran would be a fabrication.
 */
export interface ConfidenceAudit {
  /** Signals that fired. Non-empty by construction. */
  signals: DowngradeSignal[];
  /** What the signals alone would have produced, with no severity gate. */
  ungated: Confidence;
  /** Whether the gate held the downgrade back (`confidence !== ungated`). */
  floored: boolean;
}

/** Which suppression mechanism asked for the finding to disappear. */
export type SuppressionChannel = 'pragma' | 'config';

/**
 * The scope of the entry that asked. `file`/`line` are the two pragma scopes
 * (`vibeguard:disable-file` and `disable-line`/`disable-next-line`, which land
 * in the same per-line bucket and are indistinguishable once parsed); `path` is
 * the config `suppress[].paths` glob.
 */
export type SuppressionScope = 'file' | 'line' | 'path';

/**
 * A suppression that matched a finding and was refused.
 *
 * Only blanket (wildcard) suppressions can be refused, and only for severities
 * that carry a security judgement — see `SECURITY_JUDGEMENT_SEVERITIES` for the
 * boundary and why it sits where it does. An entry that names the rule ID is
 * always honoured, at every severity: naming the rule is a statement about a
 * specific finding, which is the escape hatch that keeps the mechanism usable.
 *
 * Same shape of contract as `ConfidenceAudit`, and for the same reason. The
 * event worth recording is not "this finding was suppressed" — a suppressed
 * finding is gone, there is nothing to attach the record to. It is the inverse:
 * something tried to silence a security judgement wholesale and was stopped, so
 * the finding is still here and carries the evidence of the attempt. Consumers
 * that want to flag suspicious suppressions look for the presence of this key;
 * absence is the contract for "nothing tried", so it is spread in conditionally
 * rather than set to `undefined`.
 */
export interface SuppressionOverride {
  channel: SuppressionChannel;
  scope: SuppressionScope;
  /** `reason=`/`reason:` text from the refused entry, when it carried one. */
  reason?: string;
}

/**
 * One aggregated line of "a suppression matched, and a finding is gone because
 * of it" — D8.
 *
 * THIS IS NOT A DEFENCE. Nothing here stops a suppression; every finding counted
 * by a record has already been dropped and will not appear in `findings`, the
 * summary, or the exit code. The mechanism this documents (naming a rule ID in a
 * pragma or in `suppress[].rules`) is honoured at every severity by design — see
 * `SECURITY_JUDGEMENT_SEVERITIES` and `entryCovers` for why the escape hatch has
 * to stay open. What changes is only that using it is no longer *silent*: before
 * this, a scan output was byte-identical whether a critical finding never
 * existed or whether someone had written one line to erase it. That
 * indistinguishability is what made suppression usable as a hiding mechanism,
 * and it is the only thing removed here. An attacker can still suppress; they
 * can no longer suppress without leaving a countable trace in the artifact the
 * reviewer reads.
 *
 * `SuppressionOverride` is the complement of this type and the two must not be
 * confused. That one rides on a finding that SURVIVED a refused blanket
 * suppression; this one stands in for findings that did NOT survive an honoured
 * one.
 *
 * WHAT IS DELIBERATELY NOT HERE: the finding itself — no title, no snippet, no
 * line numbers. Two reasons, and the second is the load-bearing one.
 *  - Re-emitting the suppressed content would make suppression a no-op, which
 *    would break the legitimate use (the noise a team asked not to see would
 *    come back in a different column) and would guarantee the feature gets
 *    turned off wholesale, which is strictly worse for observability.
 *  - `ruleId` plus a line number IS the finding, near enough: a reader holding
 *    both can reconstruct what was hidden without the analyzer's help. The
 *    granularity therefore stops at the FILE. "VG-INJ-004 was silenced twice in
 *    src/db.ts by a pragma" is enough for a reviewer to go look, which is the
 *    entire job of this channel, and it is not enough to serve as a findings
 *    feed that bypasses the user's stated intent.
 * `filePath` is kept because without it a directory scan can only say that
 * something somewhere was silenced, which is not actionable.
 */
export interface SuppressionRecord {
  /** The suppressed rule. `*` is never used here — records name the real rule. */
  ruleId: string;
  channel: SuppressionChannel;
  scope: SuppressionScope;
  /** File the suppression applied in. Absent for snippet scans, which have none. */
  filePath?: string;
  /** How many findings this channel+scope+rule+file combination removed. */
  count: number;
}

export interface Finding {
  findingId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  /** Context-downgrade audit trail; present only when a signal fired. */
  confidenceAudit?: ConfidenceAudit;
  /**
   * Present only when a blanket suppression matched this finding and the
   * severity gate refused it. Absence means nothing tried to suppress it.
   */
  suppressionOverridden?: SuppressionOverride;
  category: string;
  language?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: string;
  evidence?: string[];
  remediation?: Remediation;
  references?: string[];
  sourceEngine: SourceEngine;
  tags?: string[];
}

/**
 * One place in the codebase, addressed the same way `Finding` addresses its own.
 *
 * Exists because a design smell is frequently NOT at one place. `Finding` can
 * only name a single span — `filePath` + `startLine`/`endLine` — which is the
 * right shape for "this line calls `eval`" and the wrong shape for "this
 * authorization check is duplicated in five handlers across four files". The
 * whole claim of a cross-file smell is the RELATIONSHIP between locations, and a
 * schema that can only carry one of them forces the other four into prose inside
 * `description`, where no consumer can act on them: SARIF cannot link them, the
 * VS Code extension cannot offer "go to related location", and a diff-based
 * baseline cannot tell "the same smell moved" from "a new smell appeared".
 *
 * The field names deliberately mirror `Finding`'s flat ones rather than
 * inventing a parallel vocabulary (`line`/`col`, `start`/`end` objects). A
 * consumer that already knows how to render a `Finding` span can render one of
 * these with the same code, and `primaryLocation` can be checked against the
 * flat fields field-by-field — see `designSmellLocationsAgree`.
 *
 * `filePath` is REQUIRED here, unlike on `Finding` where it is optional because
 * snippet scans have no file. A related location with no file is not addressable
 * by anything downstream: it cannot be opened, linked, or deduplicated, so it
 * would be a row that exists only to be dropped. Cross-file analysis runs over a
 * directory by construction, so there is always a path to put here.
 */
export interface CodeLocation {
  filePath: string;
  startLine: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  /** The source text at this location, for rendering without re-reading the file. */
  snippet?: string;
  /**
   * What was found HERE specifically — e.g. the normalized authorization check
   * `user.role === "admin"`. On a related location this is usually the only
   * thing distinguishing it from its siblings, so it is what a report prints
   * next to the path (see the `VG-SMELL-010` report format in the design
   * addendum §12).
   */
  evidence?: string;
}

/**
 * How much of the codebase a design smell is a statement ABOUT.
 *
 * Not a severity, not a confidence, and not a size — it is the unit the finding
 * would have to be fixed at. `line` means the fix is on that line; `project`
 * means no single edit resolves it and the fix is structural. This matters for
 * two consumers that would otherwise get it wrong:
 *
 *  - Suppression. `vibeguard:disable-next-line VG-SMELL-010` is close to
 *    meaningless for a `project`-scoped finding — the "next line" is one of five
 *    equally-implicated sites, and silencing it there hides the other four. The
 *    scope is what lets a suppression channel decide whether a line pragma is
 *    even a coherent request.
 *  - Baselines and diffing. A `file`-scoped finding that moves to another line
 *    is the SAME finding; a `line`-scoped one that moves may not be. Without the
 *    scope, a differ has to guess, and it guesses wrong in the direction that
 *    produces churn.
 *
 * Ordered from narrowest to widest in the union on purpose — the declaration
 * order is the semantic order, and `DESIGN_SMELL_SCOPE_ORDER` makes that
 * machine-readable rather than a comment nobody can call.
 */
export type DesignSmellScope = 'line' | 'symbol' | 'class' | 'file' | 'module' | 'project';

/** Narrowest to widest. See `DesignSmellScope` for why the order is meaningful. */
export const DESIGN_SMELL_SCOPE_ORDER: Record<DesignSmellScope, number> = {
  line: 1,
  symbol: 2,
  class: 3,
  file: 4,
  module: 5,
  project: 6,
};

/**
 * The measurements a design-smell rule computed to reach its verdict.
 *
 * Every field is optional, and that is the design rather than laziness. A smell
 * that fires on duplicated authorization checks computes `duplicatedCheckCount`
 * and has no opinion about `nestingDepth`; forcing it to emit a zero would be a
 * fabricated measurement, indistinguishable from "measured, and it was zero".
 * Absence means NOT MEASURED. Consumers must not read a missing field as 0.
 *
 * This is the finding's evidence in the form a reader can argue with. A design
 * smell is a judgement about structure, so unlike a regex match it has no
 * offending substring to point at — "this class is doing too much" is not
 * falsifiable by looking at one line. Carrying the numbers makes the judgement
 * checkable: a reader who disagrees can see that the threshold was 3 and the
 * measurement was 5, and the disagreement becomes about the threshold rather
 * than about whether the tool is hallucinating.
 *
 * Field set is fixed by the design addendum §9 (DesignMetrics). Fields the
 * 0.3.0-α milestone does not yet compute are still declared here: the schema is
 * allowed to lead the implementation because every field is optional, and
 * declaring them up front stops each rule from inventing its own spelling of
 * `fanOut` in `tags` while it waits.
 */
export interface DesignMetrics {
  loc?: number;
  methodCount?: number;
  fieldCount?: number;
  importCount?: number;
  branchCount?: number;
  nestingDepth?: number;
  /** Number of distinct symbols that reference this one. */
  fanIn?: number;
  /** Number of distinct symbols this one references. */
  fanOut?: number;
  responsibilityCount?: number;
  /** How many places repeat the same check. The measurement behind VG-SMELL-010. */
  duplicatedCheckCount?: number;
}

/**
 * What kind of security work the implicated code is doing.
 *
 * This is the input to Security Context Boost (design addendum §10.3): the same
 * structural shape is a maintainability note in a formatting helper and a
 * security finding in a route guard, and this is where that difference is
 * recorded so the severity decision has something to cite.
 *
 * Booleans, not a string union, because these are not mutually exclusive and the
 * overlap is the interesting part — a function that does authorization AND
 * touches sensitive data is worse than one doing either, and a union would force
 * a lossy choice between them at the moment the evidence is richest.
 *
 * Optional for the same reason `DesignMetrics` fields are: absent means the
 * analysis did not look, which is not the same as looked-and-found-nothing.
 * A boost must therefore treat `undefined` as "no evidence to boost on" and
 * leave severity alone, never as `false`.
 *
 * NOT here, deliberately: anything derived from the pull request or the diff.
 * The design addendum §10.3 lists "code newly added in a PR diff" as a boost
 * condition, and §5.4 of the implementation plan overrides it — severity must
 * not depend on which diff the file was scanned in, or the same code produces
 * different verdicts on the PR and on `main`, which breaks both reproducibility
 * and every baseline built from it. The two primary sources conflict; §5.4 is
 * the later decision and wins. Leaving the field out of the schema is what makes
 * the resolution enforceable rather than a note someone can miss.
 */
export interface SecurityContext {
  containsAuthLogic?: boolean;
  containsAuthorizationLogic?: boolean;
  containsValidationLogic?: boolean;
  containsCryptoLogic?: boolean;
  containsTokenLogic?: boolean;
  containsSensitiveDataFlow?: boolean;
}

/**
 * The category every design-smell finding carries, single-file and cross-file
 * alike.
 *
 * A named constant rather than a literal at each call site because it is a
 * PARTITION KEY, not a label. The regression contract for 0.3.0-α is that
 * turning cross-file analysis on adds findings in this category and changes
 * nothing outside it — `samples/vulnerable` must still produce its 51 findings,
 * with identical ids, when design smells are enabled. That test is written as
 * "filter this category out and compare", so the string has to be the same one
 * the producers use, and a typo in either half would make the test pass by
 * comparing two empty sets.
 */
export const DESIGN_SMELL_CATEGORY = 'security-design-smell';

/**
 * A `Finding` that is a statement about STRUCTURE rather than about a line.
 *
 * Extends rather than replaces, and that inheritance is load-bearing: every
 * consumer downstream — the SARIF adapter, the CLI formatters, `--fail-on`,
 * suppression, the summary counts — operates on `Finding` and must keep working
 * on these without modification. A design smell that needed a parallel pipeline
 * would be a second product. So the flat `filePath`/`startLine` fields inherited
 * from `Finding` stay populated and stay authoritative for anything that only
 * knows about `Finding`; the additions here are strictly extra information for
 * consumers that know to look.
 *
 * That leaves one hazard worth naming, because it is the failure this schema is
 * most likely to produce: `primaryLocation` and the inherited flat fields say
 * the same thing twice, and two sources of truth drift. They are kept anyway,
 * because the alternative — dropping the flat fields — breaks every existing
 * consumer, and the other alternative — dropping `primaryLocation` — makes the
 * primary location the only one of the N locations with a different shape, so
 * code that walks "all locations of this finding" has to special-case the first.
 * The duplication is therefore deliberate and CHECKED rather than trusted:
 * `designSmellLocationsAgree` is the predicate, and producers are expected to
 * build these through a constructor that derives one from the other rather than
 * writing both by hand.
 *
 * `scope` is required while everything else is optional. A design smell with no
 * declared scope is the one thing consumers cannot recover from — they would
 * have to guess whether a line pragma can suppress it — and unlike the metrics
 * there is no honest "not measured" value, since a rule always knows what unit
 * it is judging.
 */
export interface DesignSmellFinding extends Finding {
  scope: DesignSmellScope;
  /**
   * The structured form of the location already in `filePath`/`startLine`.
   * Must agree with them — see `designSmellLocationsAgree`.
   */
  primaryLocation?: CodeLocation;
  /**
   * The other places implicated in the same smell. For VG-SMELL-010 these are
   * the duplicate authorization checks; the finding's claim is about the SET,
   * and reading `primaryLocation` alone understates it.
   *
   * Does NOT include `primaryLocation`. Consumers wanting every site should
   * concatenate, which `allDesignSmellLocations` does.
   */
  relatedLocations?: CodeLocation[];
  metrics?: DesignMetrics;
  securityContext?: SecurityContext;
}

/**
 * Whether a finding is a design smell, by category rather than by shape.
 *
 * Shape would be the obvious test — "does it have a `scope`?" — and it is the
 * wrong one: it decides membership from whichever producer happened to fill a
 * field in, so a rule that forgot `scope` would silently fall out of the
 * partition and land back in the set that E2 counts. Category is what the
 * partition contract is written in terms of, so it is what this asks.
 */
export function isDesignSmellFinding(finding: Finding): finding is DesignSmellFinding {
  return finding.category === DESIGN_SMELL_CATEGORY;
}

/**
 * Whether `primaryLocation` says the same thing as the inherited flat fields.
 *
 * The guard for the deliberate duplication documented on `DesignSmellFinding`.
 * A finding with no `primaryLocation` trivially agrees — the field is optional,
 * and absence is not a contradiction.
 *
 * Compares only the fields the flat form has. `snippet` and `evidence` are not
 * checked: `Finding.evidence` is a `string[]` of a different shape than
 * `CodeLocation.evidence`, and demanding they match would be inventing a
 * constraint neither producer nor consumer needs.
 */
export function designSmellLocationsAgree(finding: DesignSmellFinding): boolean {
  const p = finding.primaryLocation;
  if (!p) return true;
  return (
    p.filePath === finding.filePath &&
    p.startLine === finding.startLine &&
    (p.endLine ?? finding.endLine) === finding.endLine &&
    (p.startColumn ?? finding.startColumn) === finding.startColumn &&
    (p.endColumn ?? finding.endColumn) === finding.endColumn
  );
}

/**
 * Every location a design smell implicates, primary first.
 *
 * The order is part of the contract: the primary location is the one the finding
 * is filed under and the one a reader is taken to first, so a renderer that
 * prints this list in order matches where the finding claims to live. Related
 * locations keep the order the producer emitted them in — for VG-SMELL-010 that
 * is the deterministic path-sorted scan order, so two runs over the same tree
 * produce the same list and a baseline diff stays empty.
 */
export function allDesignSmellLocations(finding: DesignSmellFinding): CodeLocation[] {
  const primary =
    finding.primaryLocation ??
    (finding.filePath !== undefined && finding.startLine !== undefined
      ? { filePath: finding.filePath, startLine: finding.startLine, endLine: finding.endLine }
      : undefined);
  return [...(primary ? [primary] : []), ...(finding.relatedLocations ?? [])];
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanContext {
  workingDirectory?: string;
  projectName?: string;
  isAIGenerated?: boolean;
  framework?: string;
}

export interface ScanRequest {
  targetType: TargetType;
  content?: string;
  filePath?: string;
  language?: string;
  mode: ScanMode;
  includeExternalScanners?: boolean;
  includeRemediation?: boolean;
  context?: ScanContext;
}

/**
 * A rule whose `match` threw and was skipped during a scan. The analyzer catches
 * a throwing rule so one broken rule cannot crash the whole scan — but skipping
 * it silently drops every finding it would have produced, an undeclared
 * suppression channel (crash the rule, lose the findings, no signal anywhere).
 * Carrying the crash on the response makes it observable rather than silent: the
 * CLI surfaces it in every format (human, markdown, JSON, SARIF). The VS Code and
 * Chrome extensions receive it on the response but do not yet render it in their
 * UI — surfacing it there is tracked separately.
 */
export interface RuleError {
  ruleId: string;
  message: string;
}

/**
 * A scan that COMPLETED but saw less than the whole input — a partial result,
 * not a crash.
 *
 * Kept SEPARATE from `RuleError` on purpose. A rule error means "this rule threw
 * and produced nothing"; a degradation means "this rule ran and produced
 * findings, but a ReDoS bound stopped it before it had searched everything". The
 * two demand opposite words to the user ("skipped, no findings" vs "ran, results
 * may be incomplete"), so folding them into one channel guarantees the rendering
 * lies about one of them — which it did: the CLI's rule-error wording
 * ("errored and were skipped — findings NOT reported") is false for a truncation.
 *
 * `kind`:
 *  - `input-truncated`: the file exceeded the regex input cap and only its
 *    prefix was scanned (`scannedChars` of `totalChars`).
 *  - `deadline-exceeded`: a rule's matching passed the scan-wide time budget and
 *    was cut off after `matchCount` matches.
 *  - `match-limit`: a rule hit the per-file match ceiling, so an UNKNOWN number
 *    of further matches of that rule exist in the file and were never reported.
 *    A1-LIMIT. Emitted only for rules whose severity is a security judgement
 *    (`isSecurityJudgementSeverity`); low/info rules hit this cap routinely and
 *    benignly, and reporting those would bury the cases that matter. The cap
 *    itself is NOT lifted — it is what bounds the A1 availability attack — so
 *    this degradation makes the truncation visible without giving the bound up.
 *
 *    `matchCount` is the ceiling, i.e. how many matches WERE reported, not how
 *    many existed. The excess is not knowable: matching stops at the cap.
 *
 * `filePath` is carried so a directory scan can name WHICH file degraded — the
 * one thing a `ruleId`-keyed channel could not express.
 */
export interface ScanDegradation {
  kind: 'input-truncated' | 'deadline-exceeded' | 'match-limit';
  ruleId: string;
  filePath?: string;
  /** Human-readable, actionable, and explicit that the result is partial. */
  detail: string;
  scannedChars?: number;
  totalChars?: number;
  matchCount?: number;
}

export interface ScanResponse {
  summary: ScanSummary;
  findings: Finding[];
  executionTimeMs: number;
  engineVersions: Record<string, string>;
  generatedAt: string;
  /** Rules that threw during `match` and were skipped. Present only when non-empty. */
  ruleErrors?: RuleError[];
  /**
   * Rules whose scan was cut short by a ReDoS bound (input cap or time budget).
   * A partial scan, surfaced so it is never mistaken for a clean one. Present
   * only when non-empty.
   */
  degradations?: ScanDegradation[];
  /**
   * Findings that a suppression removed from this scan, aggregated per
   * rule+channel+scope+file. Observability only — see `SuppressionRecord`. These
   * do NOT contribute to `summary`, do NOT appear in `findings`, and do NOT
   * affect the CLI exit code (same posture as `degradations`: a signal to a
   * reader, not a gate). Present only when non-empty, so a scan that suppressed
   * nothing is byte-identical to what it produced before D8.
   */
  suppressions?: SuppressionRecord[];
}

export function emptySummary(): ScanSummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
}

export function summarize(findings: Finding[]): ScanSummary {
  const summary = emptySummary();
  for (const f of findings) {
    summary[f.severity] += 1;
    summary.total += 1;
  }
  return summary;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

/**
 * Which severities carry a *security judgement*, i.e. a verdict a consumer acts
 * on rather than a piece of hygiene advice.
 *
 * This is the shared boundary behind every "utility may not overrule security"
 * enforcement point in the codebase. `SEVERITY_CONFIDENCE_FLOOR` (paper item
 * ①c, packages/rules/src/confidence.ts) established the principle on the
 * *confidence* axis: a context downgrade is noise reduction, and noise reduction
 * must never be able to decide a security question, so the downgrade is bounded
 * for findings whose impact would be severe if real. The same principle applies
 * to every other mechanism that can make a finding quieter — suppression
 * (`vibeguard:disable-*` pragmas and the config `suppress` paths) and the
 * truncation that happens when a rule hits its per-file match cap. Rather than
 * let each of those re-derive "which findings are severe enough to protect",
 * they all ask this predicate, so the policy is one decision with several
 * enforcement points instead of several policies that drift apart.
 *
 * The line is drawn at `medium`, following the precedent set by the confidence
 * floor rather than inventing a second boundary. Two observations put it there:
 *
 *  - `medium` is above the default actionable threshold. A consumer running the
 *    default configuration acts on medium findings, so a mechanism that can
 *    silence them silently removes something that would otherwise have been
 *    acted on. That is the property that matters, and it does not change
 *    between the confidence axis and the suppression axis.
 *  - Measurement on the confidence axis (item ①c) showed the un-bounded
 *    `medium` band was where the disguise actually worked: a real finding was
 *    pushed below the line just as effectively as it would have been in the
 *    `high` band without a gate. There is no reason to expect the suppression
 *    axis to behave differently, and the corpus generator for the b3 attack
 *    (scripts/sec-b3-gen-corpus.mjs, the suppress-wildcard arm) is explicitly
 *    severity-agnostic — it fires a blanket `vibeguard:disable-file` and takes
 *    whatever it happens to cover. A boundary that stopped at `high` would hand
 *    that arm the entire `medium` band for free.
 *
 * `low` and `info` deliberately stay outside. These are the bands where the
 * findings are advisory (style, hygiene, "consider…") and where blanket
 * suppression is the legitimate day-to-day operation that keeps VibeGuard
 * usable on a real codebase — a team that has decided it does not care about a
 * class of `low` findings must be able to say so once and move on. Excluding
 * them is not a weaker application of the principle; it is the principle,
 * which is about *security* judgements specifically. Utility mechanisms keep
 * full authority over the bands that carry no security verdict.
 *
 * Deliberately a total `Record` rather than a set or a `Partial`, for the same
 * reason `SEVERITY_CONFIDENCE_FLOOR` is: adding a severity to the schema must
 * break this build and force an explicit decision about which side of the line
 * it falls on, instead of silently defaulting to "not a security judgement" —
 * the quiet direction is the unsafe one.
 */
export const SECURITY_JUDGEMENT_SEVERITIES: Record<Severity, boolean> = {
  critical: true,
  high: true,
  medium: true,
  low: false,
  info: false,
};

/**
 * The predicate form of `SECURITY_JUDGEMENT_SEVERITIES`. Enforcement points
 * should call this rather than index the record directly, so the record stays a
 * private-by-convention lookup table and the call sites read as the policy
 * question they are asking ("is this a security judgement?") instead of as a
 * table lookup.
 */
export function isSecurityJudgementSeverity(severity: Severity): boolean {
  return SECURITY_JUDGEMENT_SEVERITIES[severity];
}

export const CONFIDENCE_ORDER: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Mirrors `compareSeverity`: negative when `a` ranks above `b`, zero when equal.
 * So `compareConfidence(f.confidence, threshold) <= 0` reads "at least as
 * confident as the threshold", matching the severity idiom used for --fail-on.
 */
export function compareConfidence(a: Confidence, b: Confidence): number {
  return CONFIDENCE_ORDER[b] - CONFIDENCE_ORDER[a];
}

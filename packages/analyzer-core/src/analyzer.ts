import {
  emptySummary,
  summarize,
  compareSeverity,
  isSecurityJudgementSeverity,
  type Finding,
  type RuleError,
  type ScanDegradation,
  type ScanMode,
  type ScanRequest,
  type ScanResponse,
  type Severity,
} from '@vibeguard/findings-schema';
import {
  allRules,
  captureRegexBoundaries,
  withScanDeadline,
  REGEX_DEADLINE_MS,
  REGEX_INPUT_CAP,
  REGEX_MATCH_LIMIT,
  explainContextConfidence,
  languageMatches,
  type RegexBoundaryEvent,
  type RuleContext,
  type RuleDefinition,
  type RuleMatch,
} from '@vibeguard/rules';
import { buildRemediation } from '@vibeguard/remediation-engine';
import { canonicalize, canonicalizePreprocessor } from './canonicalizer.js';
import { detectLanguageFromContent, detectLanguageFromPath } from './language-detect.js';
import { extractSnippet, maskSecret } from './snippet.js';
import {
  parseSuppressions,
  evaluateSuppression,
  tallySuppression,
  collectSuppressions,
  type SuppressionTally,
} from './suppress.js';

/**
 * Detection-engine version, embedded in every scan result and SARIF report
 * (`engineVersions.core`). This is a SEPARATE axis from the released tool /
 * package version (package.json): bump it only when detection behavior changes
 * (rules, analysis, finding schema) — not for packaging, UX, or docs releases.
 * It deliberately stayed at 0.1.0 across tool releases 0.1.1–0.1.3, which did
 * not alter what VibeGuard detects.
 *
 * 0.2.0 (2026-07-20) ends a deliberate hold. The bump was deferred while a round
 * of detection changes was in flight, so that one version names ONE settled
 * engine rather than several successive ones. During the hold `engineVersions.core`
 * knowingly understated the engine and did NOT satisfy the "same engine ⇒
 * identical verdicts" contract in README.md; that debt is discharged here, and
 * `paper-ses-v0.1.3` remains the tag to compare against for the pre-hold engine.
 *
 * What 0.2.0 names, i.e. every change to detection behavior made under the hold:
 *
 *   - Context-window confidence, and its severity gate
 *     (`SEVERITY_CONFIDENCE_FLOOR` in @vibeguard/rules): critical/high/medium
 *     findings keep their declared confidence in contexts that previously
 *     down-ranked them. Down-ranking is triage, never a security verdict.
 *   - The canonicalizer pre-pass: rules also run over normalized text, so
 *     lexically evaded payloads (`"ev" + "al"`, `eval/*x*\/(…)`) are detected
 *     where they were not. The union can only ADD findings. Toggle with
 *     `AnalyzerOptions.canonicalize`.
 *   - Regex time and input-length bounds, plus `ScanDegradation`: a scan that
 *     stopped early now says so instead of looking clean. (Schema change.)
 *   - `confidenceAudit` on findings: the reasoning behind a confidence value is
 *     carried rather than recomputed. Values are unchanged. (Schema change.)
 *   - The suppression severity gate: a wildcard `vibeguard:disable` no longer
 *     silences critical/high/medium findings, on both the pragma and the config
 *     channel. Naming a rule still works at every severity. (BREAKING.)
 *   - `match-limit` degradations: hitting the per-file match cap on a
 *     security-severity rule is now reported instead of dropped. (Schema change.)
 *   - `ScanResponse.suppressions`: findings removed by a suppression are tallied,
 *     so concealment is on the record rather than indistinguishable from absence.
 *     Observability, not a defence — the suppression still applies. (Schema change.)
 *
 * The next bump is due when detection behavior changes again; there is no hold
 * in effect. `engine-version-pin.test.ts` guards this value and the docs that
 * quote it, and carries the checklist for changing it.
 *
 * 0.2.1 (2026-07-21) names the C/C++/Arduino embedded layer (VG-EMB): the
 * `.ino`/`.hh`/`.cxx`/`.ipp` extensions, the N_pp preprocessor-branch
 * normalization face (a third union term, C/C++ only), and 19 new rules across
 * VG-MEM / VG-EMB / VG-RTOS. This is a detection-behavior change (new rules, new
 * languages, a new normalization face), so the engine moves even though it is
 * purely ADDITIVE: web-language verdicts are untouched (E2=51 / E3=0 hold), and
 * the released `v0.2.0` / `paper-css-v0.2.0` tags remain the immutable baseline
 * for the pre-embedded engine. Nothing else about detection changed.
 */
export const ENGINE_VERSION = '0.2.1';

let counter = 0;
function findingId(): string {
  counter += 1;
  return `vg-${Date.now().toString(36)}-${counter.toString(36)}`;
}

function shouldMaskCategory(category: string): boolean {
  return category === 'secrets';
}

function filterRulesByMode(rules: RuleDefinition[], mode: ScanMode): RuleDefinition[] {
  if (mode === 'fast') {
    return rules.filter((r) => r.severity === 'critical' || r.severity === 'high');
  }
  // 'standard' and 'deep' run all rules. Future: 'deep' will also dispatch to
  // external scanners when request.includeExternalScanners is true.
  return rules;
}

/**
 * Turn D3's regex bounds into `degradations` — a channel SEPARATE from
 * `ruleErrors`.
 *
 * The first version routed these through `ruleErrors`, and that was wrong: the
 * CLI renders `ruleErrors` under "rule(s) errored and were skipped — findings
 * NOT reported", which is the opposite of what a truncation is (the rule ran and
 * DID report findings, just not past the cap). A degradation carries its own
 * kind and its `filePath`, so a directory scan can name the file, and the
 * renderer can use words that are true.
 *
 * DEDUPLICATED PER RULE AND KIND. A rule holding seven patterns (VG-CRYPTO-002)
 * would otherwise emit seven identical truncation entries for one oversized
 * file, burying the signal. The first event of each kind carries the report.
 *
 * A1-LIMIT — `limitReached` is surfaced BY SEVERITY, not dropped wholesale.
 *
 * The previous rule here was "never surface it": the cap fires on any file with
 * more than REGEX_MATCH_LIMIT matches of one rule, which is common and usually
 * benign, and flooding this channel with it would train readers to ignore the
 * two bounds that do matter. That reasoning holds for quality rules and only for
 * quality rules. Measured on a 1500-`eval` file, the old behaviour reported
 * exactly 1000 critical findings, 500 more that existed were dropped, and
 * `degradations` came back empty — a scan that had silently stopped counting
 * looked byte-for-byte like a scan that was complete. That is the same failure
 * mode D5 closes on the suppression side: a utility-grade convenience deciding a
 * security question in silence.
 *
 * So the split follows the SAME boundary as D5 and D1c, through the same shared
 * predicate: if the rule's severity is one the tool's security judgement rests
 * on (critical/high/medium per `isSecurityJudgementSeverity`), the truncation is
 * reported; low/info keep the old silence. One principle, one predicate, three
 * enforcement points.
 *
 * Two things this deliberately does NOT do:
 *  - It does not raise or remove the cap. The cap is what bounds A1's
 *    availability attack; A1-LIMIT only makes its effect visible.
 *  - It does not emit one degradation per lost finding. The report is aggregated
 *    to ONE entry per (file, rule) — see the dedup below — so the channel stays
 *    readable no matter how many matches were cut. It also cannot state the
 *    excess, because matching stopped at the cap and never counted the rest;
 *    saying "500 were dropped" would be a number nobody measured.
 */
function recordBoundaries(
  degradations: ScanDegradation[],
  ruleId: string,
  severity: Severity,
  events: RegexBoundaryEvent[],
  filePath: string | undefined,
  pass?: string,
): void {
  recordMatchLimit(
    degradations,
    ruleId,
    severity,
    events.filter((e) => e.kind === 'limitReached'),
    filePath,
  );

  const reportable = events.filter((e) => e.kind !== 'limitReached');
  if (reportable.length === 0) return;
  const byKind = new Map<RegexBoundaryEvent['kind'], { first: RegexBoundaryEvent; count: number }>();
  for (const e of reportable) {
    const seen = byKind.get(e.kind);
    if (seen) seen.count += 1;
    else byKind.set(e.kind, { first: e, count: 1 });
  }
  for (const [kind, { first, count }] of byKind) {
    const where = pass ? ` on ${pass}` : '';
    const more = count > 1 ? ` (+${count - 1} more pattern${count > 2 ? 's' : ''} in this rule)` : '';
    if (kind === 'truncated') {
      degradations.push({
        kind: 'input-truncated',
        ruleId,
        filePath,
        scannedChars: REGEX_INPUT_CAP,
        totalChars: first.inputLength,
        detail: `ReDoS guard${where}: only the first ${REGEX_INPUT_CAP} of ${first.inputLength} chars were scanned${more}. Findings beyond that point were not searched for — this result is PARTIAL.`,
      });
    } else {
      degradations.push({
        kind: 'deadline-exceeded',
        ruleId,
        filePath,
        matchCount: first.matchCount,
        detail: `ReDoS guard${where}: matching exceeded the ${REGEX_DEADLINE_MS}ms budget after ${first.matchCount} match(es)${more}. Findings beyond that point were not searched for — this result is PARTIAL.`,
      });
    }
  }
}

/**
 * A1-LIMIT — emit at most ONE `match-limit` degradation per (file, rule).
 *
 * Aggregation is not cosmetic here, it is what keeps the channel usable. A rule
 * carrying seven patterns can raise seven `limitReached` events for one file,
 * and `recordBoundaries` is called twice per rule (original text, then canonical
 * text), so the unaggregated count for a single oversized file is patterns ×
 * passes. Collapsing on (filePath, ruleId) bounds the whole scan at one entry
 * per file per rule — the same shape the CLI already deduplicates degradations
 * into, so a directory scan cannot be flooded from one crafted file either.
 *
 * The dedup scans `degradations` rather than carrying a Set because the array is
 * the single source of truth across BOTH passes; a per-call Set would reset
 * between them and let the canonical pass emit a duplicate of what the original
 * pass already reported.
 */
function recordMatchLimit(
  degradations: ScanDegradation[],
  ruleId: string,
  severity: Severity,
  events: RegexBoundaryEvent[],
  filePath: string | undefined,
): void {
  if (events.length === 0) return;
  // The severity gate. Quality rules keep the pre-A1-LIMIT silence.
  if (!isSecurityJudgementSeverity(severity)) return;
  const already = degradations.some(
    (d) => d.kind === 'match-limit' && d.ruleId === ruleId && d.filePath === filePath,
  );
  if (already) return;

  degradations.push({
    kind: 'match-limit',
    ruleId,
    filePath,
    // What was REPORTED, not what existed. See REGEX_MATCH_LIMIT: the matches
    // past the cap are never enumerated, so the excess has no honest number.
    matchCount: REGEX_MATCH_LIMIT,
    detail:
      `Match limit: this rule reported the first ${REGEX_MATCH_LIMIT} match(es) in this file and stopped. ` +
      `Further matches of a ${severity}-severity rule exist and were NOT reported — their count is unknown, ` +
      `because matching stops at the cap. This result is PARTIAL. The cap is a deliberate availability bound ` +
      `and is not raised; split the file or scan the region directly to see the rest.`,
  });
}

function buildRuleContext(content: string, language: string | undefined, filePath: string | undefined): RuleContext {
  return {
    content,
    lines: content.split('\n'),
    language,
    filePath,
  };
}

export interface AnalyzerOptions {
  /** Override which rules participate. Defaults to allRules. */
  rules?: RuleDefinition[];
  /** Skip remediation generation (CI-light scans). */
  skipRemediation?: boolean;
  /**
   * Run the D2 normalization pre-pass (see canonicalizer.ts). Defaults to true.
   *
   * Setting this false reproduces the pre-D2 engine exactly, which is what the
   * B1 evasion A/B harness measures against. It is an experiment control rather
   * than a user-facing switch: because the canonical pass can only ADD findings
   * (`D′(x) = D(x) ∪ D(N(x))`), turning it off can only lose detections, never
   * fix a false positive.
   */
  canonicalize?: boolean;
  /**
   * Run the N_pp preprocessor arm (see canonicalizer.ts), the third union face
   * for C/C++: `D′(x) = D(x) ∪ D(N(x)) ∪ D(N_pp(x))`. Defaults to true, and is
   * additionally gated by `canonicalize` — with normalization off entirely there
   * is no N_pp either.
   *
   * Its own switch exists for the ablation ladder (D vs D∪N vs D∪N∪N_pp): set
   * `preprocessorFace: false` with `canonicalize: true` to measure the middle
   * rung. Like `canonicalize`, it can only ADD findings, so disabling
   * it only loses detections on C/C++ preprocessor-split payloads.
   */
  preprocessorFace?: boolean;
}

/**
 * Where a match's payload actually begins, as `line:column`.
 *
 * NOT simply `(startLine, startColumn)`, and the difference is the whole point.
 * Many rules anchor with `^\s*…` under the `m` flag, and `\s` matches newlines,
 * so a match can begin at the blank tail of an earlier line. Canonicalization
 * makes that strictly more common: blanking a comment turns its line into
 * whitespace, which such a pattern can then reach back across. The same
 * `DEBUG = True` therefore matches at line 6 on the original text and at line 3
 * on the canonical text — one finding, two start positions.
 *
 * Keying on the first non-whitespace character of the evidence collapses both
 * to the same anchor, so the pair is recognised as the duplicate it is. This is
 * the same correction `inspectedLine` in confidence.ts applies for the same
 * reason.
 */
function anchorMatch(m: RuleMatch): RuleMatch {
  const ev = m.evidence ?? '';
  const firstNonWs = ev.search(/\S/);
  if (firstNonWs <= 0) return m;

  let newlines = 0;
  let lastNewline = -1;
  for (let i = 0; i < firstNonWs; i++) {
    if (ev[i] === '\n') {
      newlines += 1;
      lastNewline = i;
    }
  }
  return {
    ...m,
    startLine: m.startLine + newlines,
    // Still on the start line: leading whitespace only shifts the column.
    // Otherwise the column restarts after the last newline crossed.
    startColumn: newlines === 0 ? m.startColumn + firstNonWs : firstNonWs - lastNewline,
    evidence: ev.slice(firstNonWs),
  };
}

/** True when two matches of the same rule cover overlapping source. */
function overlaps(a: RuleMatch, b: RuleMatch): boolean {
  const before = (l1: number, c1: number, l2: number, c2: number): boolean =>
    l1 < l2 || (l1 === l2 && c1 < c2);
  return (
    before(a.startLine, a.startColumn ?? 0, b.endLine, b.endColumn ?? 0) &&
    before(b.startLine, b.startColumn ?? 0, a.endLine, a.endColumn ?? 0)
  );
}

/**
 * Merge the canonical pass's matches into the original pass's.
 *
 * Deduped per rule by SOURCE OVERLAP, not by equal start position, because
 * normalization moves a match in two different ways:
 *
 *   - Blanking a comment turns its line into whitespace, so a `^\s*`-anchored
 *     pattern under `/m` reaches further back and starts EARLIER.
 *   - Folding rewrites `"-" + "AKIA…"` as `"-AKIA…"` left-aligned in the span,
 *     so the payload starts EARLIER within the line.
 *
 * Either way the canonical match still covers the same source as the original
 * one, and two matches of one rule over overlapping text are one finding. Exact
 * position comparison misses both cases and reports the same secret twice.
 *
 * The ORIGINAL match wins a collision: its evidence and position describe the
 * text the user actually wrote. Only matches the original pass could not see at
 * all — the de-obfuscated ones — are appended, and those are re-anchored to
 * their payload so the finding points at the real line rather than at whatever
 * blank run the pattern happened to start in. Without that, a canonical-only
 * finding on CRLF input lands on the wrong line and no `vibeguard:disable-line`
 * on the payload line can suppress it.
 */
function mergeCanonicalMatches(original: RuleMatch[], canonical: RuleMatch[]): RuleMatch[] {
  if (canonical.length === 0) return original;
  const merged = [...original];
  for (const m of canonical) {
    if (merged.some((o) => overlaps(o, m))) continue;
    merged.push(anchorMatch(m));
  }
  return merged;
}

export class Analyzer {
  private readonly rules: RuleDefinition[];
  private readonly canonicalizeEnabled: boolean;
  private readonly preprocessorFaceEnabled: boolean;

  constructor(options: AnalyzerOptions = {}) {
    this.rules = options.rules ?? allRules;
    this.canonicalizeEnabled = options.canonicalize !== false;
    // Gated by BOTH switches: N_pp is a face of the same normalization, so
    // `canonicalize: false` turns it off regardless, and `preprocessorFace:
    // false` turns off only this face for the A/B ablation.
    this.preprocessorFaceEnabled = this.canonicalizeEnabled && options.preprocessorFace !== false;
  }

  scan(request: ScanRequest): ScanResponse {
    const start = Date.now();
    const findings: Finding[] = [];
    const ruleErrors: RuleError[] = [];
    const degradations: ScanDegradation[] = [];
    // D8: what the pragma channel silenced. Observability, not enforcement — the
    // findings counted in here are dropped either way; the only difference is
    // that the drop is now countable by whoever reads the response.
    const suppressionTally: SuppressionTally = new Map();

    if (!request.content) {
      return {
        summary: emptySummary(),
        findings,
        executionTimeMs: 0,
        engineVersions: { core: ENGINE_VERSION, rules: String(this.rules.length) },
        generatedAt: new Date().toISOString(),
      };
    }

    const language =
      request.language ??
      (request.filePath ? detectLanguageFromPath(request.filePath) : undefined) ??
      detectLanguageFromContent(request.content);

    // `this.rules`, NOT a language-filtered slice of the global registry. The
    // per-rule `languageMatches` guard in the loop below already drops rules
    // that do not apply to this language, so pre-filtering here was redundant —
    // and it pre-filtered the WRONG set: `getRulesForLanguage` reads the global
    // registry, so whenever a language was detected (i.e. almost always) a
    // caller's `options.rules` was silently replaced by every shipped rule. The
    // override only appeared to work on input whose language could not be
    // detected. It also made `engineVersions.rules` a lie, since that reports
    // `this.rules.length` while a different set actually ran.
    const baseRules = this.rules;
    const mode: ScanMode = request.mode ?? 'standard';
    const candidateRules = filterRulesByMode(baseRules, mode);
    const ctx = buildRuleContext(request.content, language, request.filePath);
    const suppressions = parseSuppressions(request.content);

    // D2 — the normalization pre-pass. `ctx` deliberately keeps the ORIGINAL
    // content: rules run over both, and the results are unioned (see
    // canonicalizer.ts for why replacing the content would be unsound). When
    // canonicalization is a no-op for this input there is nothing a second pass
    // could find, so it is skipped entirely.
    const canonical = this.canonicalizeEnabled ? canonicalize(request.content, language) : undefined;
    const canonicalCtx = canonical?.changed
      ? buildRuleContext(canonical.content, language, request.filePath)
      : undefined;

    // D2 — the N_pp preprocessor face (third union term, C/C++ only). Skipped
    // when it adds nothing over the faces already scanned: `changed` is false
    // when the input holds no directives (or is not a preprocessor language),
    // and the `!==` guard drops the pass when directive-blanking collapsed the
    // text to exactly the N face — a common case, since real C files that N
    // already touches often have no code the directives were splitting. The
    // pass is NOT deduped against the ORIGINAL here because `changed` already
    // means `content !== request.content`.
    const pp = this.preprocessorFaceEnabled
      ? canonicalizePreprocessor(request.content, language)
      : undefined;
    const ppCtx =
      pp?.changed && pp.content !== canonical?.content
        ? buildRuleContext(pp.content, language, request.filePath)
        : undefined;

    // D3 — one wall-clock budget for the whole rule loop. The per-rule captures
    // inside inherit this deadline instead of restarting it, so the bound is on
    // the scan the user waits for rather than on each of ~84 `runRegex` calls
    // individually, which would bound nothing.
    withScanDeadline(() => {
    for (const rule of candidateRules) {
      if (!languageMatches(rule.languages, language)) continue;
      let matches;
      try {
        // D3 — the regex bounds in `runRegex` report themselves here rather than
        // throwing. Throwing would land in the catch below, which discards the
        // rule entirely: a scan that merely truncated a large file would lose
        // every finding that rule had already produced. Capturing instead keeps
        // the partial matches AND names the bound, so "we stopped early" is
        // never indistinguishable from "there was nothing to find".
        const captured = captureRegexBoundaries(() => rule.match(ctx), { inheritDeadline: true });
        matches = captured.result;
        recordBoundaries(degradations, rule.ruleId, rule.severity, captured.events, request.filePath);
      } catch (err) {
        // A broken rule should never crash the scan; skip it and continue. But
        // skipping silently drops every finding it would have produced, so record
        // the crash in `ruleErrors` — otherwise this is an undeclared suppression
        // channel (the stderr line below is invisible on the browser/extension path).
        // eslint-disable-next-line no-console
        console.error(`[vibeguard] rule ${rule.ruleId} threw:`, err);
        ruleErrors.push({
          ruleId: rule.ruleId,
          message: err instanceof Error ? err.message : String(err),
        });
        continue;
      }
      // The canonical pass runs in its OWN try/catch, NOT folded into the one
      // above. A rule that throws only on the normalized text must not discard
      // the matches the original pass already produced: an earlier version
      // shared one try, so a canonical-only crash dropped the whole rule and the
      // true arm could report FEWER findings than the false arm — a direct
      // counterexample to the union guarantee `D′(x) ⊇ D(x)` that canonicalizer.ts
      // claims by construction. Record the crash like any other, but keep the
      // base matches so the guarantee holds even when a rule is canonical-hostile.
      if (canonicalCtx) {
        try {
          const capturedCanonical = captureRegexBoundaries(() => rule.match(canonicalCtx), {
            inheritDeadline: true,
          });
          recordBoundaries(
            degradations,
            rule.ruleId,
            rule.severity,
            capturedCanonical.events,
            request.filePath,
            'canonical text',
          );
          matches = mergeCanonicalMatches(matches, capturedCanonical.result);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(`[vibeguard] rule ${rule.ruleId} threw on canonical text:`, err);
          ruleErrors.push({
            ruleId: rule.ruleId,
            message: err instanceof Error ? err.message : String(err),
          });
        }
      }
      // The N_pp face — a THIRD pass, in its OWN try/catch for the same reason
      // the canonical pass is separated from the base one: a rule that throws
      // only on the preprocessor-blanked text must not discard the matches the
      // first two passes already produced, or the true arm could report fewer
      // findings than the false arm, breaking the `D′(x) ⊇ D(x)` union
      // guarantee. `matches` here is already `merge(base, canonical)`, so the
      // second merge yields `merge(merge(base, canonical), pp)`: the original
      // still wins every collision because it is in the base of both folds.
      if (ppCtx) {
        try {
          const capturedPp = captureRegexBoundaries(() => rule.match(ppCtx), {
            inheritDeadline: true,
          });
          recordBoundaries(
            degradations,
            rule.ruleId,
            rule.severity,
            capturedPp.events,
            request.filePath,
            'preprocessor text',
          );
          matches = mergeCanonicalMatches(matches, capturedPp.result);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(`[vibeguard] rule ${rule.ruleId} threw on preprocessor text:`, err);
          ruleErrors.push({
            ruleId: rule.ruleId,
            message: err instanceof Error ? err.message : String(err),
          });
        }
      }
      const includeRemediation = request.includeRemediation !== false;
      for (const m of matches) {
       // Building a finding from a match can throw independently of the rule's
       // own match() — maskSecret on a contract-violating null evidence, say. If
       // that escaped, a CANONICAL-only match failing here would take down the
       // whole scan while the false arm (which never saw that match) completes,
       // so the true arm would report FEWER findings — the exact `D′(x) ⊇ D(x)`
       // break the match()-level guard above already closes. Same treatment:
       // record it in `ruleErrors` and skip just this match, never the scan.
       try {
        // A blanket suppression that tried to cover a security judgement does
        // not drop the finding — it leaves a mark on it (`overridden`), which
        // is spread onto the finding below.
        const suppression = evaluateSuppression(suppressions, rule.ruleId, m.startLine, rule.severity);
        if (suppression.suppressed) {
          // Counted HERE, at the `continue`, and nowhere else. Recording next to
          // the drop is what makes the tally trustworthy: there is no second
          // path by which a finding can be suppressed, so there is no way for a
          // suppression to happen and go uncounted. `scope` comes off the
          // decision because only `evaluateSuppression` knows which of the two
          // pragma scopes matched.
          tallySuppression(suppressionTally, {
            channel: 'pragma',
            scope: suppression.scope ?? 'file',
            ruleId: rule.ruleId,
            ...(request.filePath !== undefined ? { filePath: request.filePath } : {}),
          });
          continue;
        }
        const rawSnippet = extractSnippet(ctx.lines, m.startLine, m.endLine, 0);
        const snippet = shouldMaskCategory(rule.category) ? maskSecret(rawSnippet) : rawSnippet;
        const evidence = shouldMaskCategory(rule.category) ? maskSecret(m.evidence) : m.evidence;

        // Resolve confidence through the explaining variant, so the reasoning
        // survives onto the finding instead of being recomputed (or lost).
        // `contextConfidence` is a thin wrapper over `.confidence` of this same
        // call, so routing through it here cannot move any confidence value.
        //
        // Guarded on `m.confidence == null` rather than run unconditionally:
        // a rule-supplied per-match confidence bypasses the context layer
        // entirely, and an audit trail for an evaluation that never happened
        // would be fiction. `== null` reproduces `??` exactly (null AND
        // undefined), so the bypass keeps its current semantics.
        const audit =
          m.confidence == null
            ? explainContextConfidence(
                rule.defaultConfidence,
                rule.severity,
                ctx,
                m,
                rule.contextConfidence ?? 'auto',
              )
            : undefined;

        findings.push({
          findingId: findingId(),
          ruleId: rule.ruleId,
          title: rule.name,
          description: rule.description,
          severity: rule.severity,
          confidence: m.confidence ?? audit!.confidence,
          // Conditional spread, not `confidenceAudit: undefined`: absence of the
          // key is the contract (`'confidenceAudit' in finding` is meaningful),
          // and `toEqual` distinguishes the two even though JSON does not.
          ...(audit && audit.signals.length > 0
            ? {
                confidenceAudit: {
                  signals: audit.signals,
                  ungated: audit.ungated,
                  floored: audit.floored,
                },
              }
            : {}),
          // Same conditional-spread contract: the key's absence means nothing
          // tried to suppress this finding, so it must not be present-but-false.
          ...(suppression.overridden ? { suppressionOverridden: suppression.overridden } : {}),
          category: rule.category,
          language,
          filePath: request.filePath,
          startLine: m.startLine,
          endLine: m.endLine,
          startColumn: m.startColumn,
          endColumn: m.endColumn,
          snippet,
          evidence: [evidence],
          remediation: includeRemediation ? buildRemediation(rule, m) : undefined,
          references: rule.references,
          sourceEngine: 'core-rule',
          tags: rule.tags,
        });
       } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[vibeguard] rule ${rule.ruleId} threw building a finding:`, err);
        ruleErrors.push({
          ruleId: rule.ruleId,
          message: err instanceof Error ? err.message : String(err),
        });
       }
      }
    }
    });

    findings.sort((a, b) => {
      const sev = compareSeverity(a.severity, b.severity);
      if (sev !== 0) return sev;
      const lineA = a.startLine ?? 0;
      const lineB = b.startLine ?? 0;
      return lineA - lineB;
    });

    return {
      summary: summarize(findings),
      findings,
      executionTimeMs: Date.now() - start,
      engineVersions: { core: ENGINE_VERSION, rules: String(this.rules.length) },
      generatedAt: new Date().toISOString(),
      ...(ruleErrors.length ? { ruleErrors } : {}),
      ...(degradations.length ? { degradations } : {}),
      ...(suppressionTally.size ? { suppressions: collectSuppressions(suppressionTally) } : {}),
    };
  }
}

export function scan(request: ScanRequest, options?: AnalyzerOptions): ScanResponse {
  return new Analyzer(options).scan(request);
}

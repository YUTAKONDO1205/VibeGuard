/**
 * Suppress-comment parsing.
 *
 * Recognised pragmas (case-sensitive):
 *   vibeguard:disable-line       — suppress findings on this line
 *   vibeguard:disable-next-line  — suppress findings on the following line
 *   vibeguard:disable-file       — suppress findings for the entire file
 *
 * After the directive, the rest of the line may contain (in any order):
 *   - Rule IDs (e.g. `VG-INJ-004 VG-AUTH-003`). When listed, only those rules
 *     are suppressed; when omitted, every rule is suppressed for that scope.
 *   - `until=YYYY-MM-DD` — turns this into a *temporary* suppression. Once the
 *     current date is past the until date the entry is ignored at parse time,
 *     so the underlying finding starts surfacing again automatically.
 *   - `reason="free text"` (or `reason=word`) — informational; recorded on
 *     the entry so tooling can surface it without altering matching.
 *
 * Examples:
 *   eval(payload); // vibeguard:disable-line VG-INJ-004
 *   // vibeguard:disable-next-line VG-INJ-004 until=2026-12-31 reason="ticket #42"
 *   // vibeguard:disable-file VG-AUTH-003 VG-AUTH-004
 *
 * Listing rule IDs is no longer merely good style. A directive with no rule IDs
 * is a wildcard, and a wildcard cannot suppress a finding whose severity
 * carries a security judgement (critical/high/medium — see
 * `SECURITY_JUDGEMENT_SEVERITIES` in @vibeguard/findings-schema for where the
 * line is and why). Such a finding is reported anyway, carrying a
 * `suppressionOverridden` record of the refusal. Wildcards keep working as
 * before for `low`/`info`, which is the band the blanket form exists to serve.
 */

import {
  isSecurityJudgementSeverity,
  type Severity,
  type SuppressionChannel,
  type SuppressionOverride,
  type SuppressionRecord,
  type SuppressionScope,
} from '@vibeguard/findings-schema';

const PRAGMA_RE = /vibeguard:(disable-line|disable-next-line|disable-file)\b([^\n\r]*)/g;
const RULE_ID_RE = /VG-[A-Z]+-\d+/g;
const UNTIL_RE = /\buntil\s*=\s*(\d{4}-\d{2}-\d{2})\b/;
const REASON_QUOTED_RE = /\breason\s*=\s*"([^"]*)"/;
const REASON_BARE_RE = /\breason\s*=\s*([^\s"]+)/;
const WILDCARD = '*';

export interface SuppressEntry {
  /** Rule IDs (or '*') suppressed by this directive. */
  ruleIds: Set<string>;
  /** Expiration date (inclusive, UTC). If `now > expiresAt`, the entry is dropped at parse time. */
  expiresAt?: Date;
  /** Free-form reason captured from reason="..." (informational only). */
  reason?: string;
}

export interface SuppressMap {
  /** 1-based line number → suppressions effective on that line. */
  perLine: Map<number, SuppressEntry[]>;
  /** Suppressions effective for the whole file. */
  fileWide: SuppressEntry[];
}

export interface ParseSuppressOptions {
  /** Override "now" for expiry filtering — primarily for tests. Defaults to `new Date()`. */
  now?: Date;
}

function parseUntil(text: string): Date | undefined {
  const m = text.match(UNTIL_RE);
  if (!m || !m[1]) return undefined;
  // Inclusive: until=2026-12-31 means the entry is still active on 2026-12-31.
  // We treat the day as ending at 23:59:59.999 UTC.
  const d = new Date(`${m[1]}T23:59:59.999Z`);
  if (Number.isNaN(d.getTime())) return undefined;
  return d;
}

function parseReason(text: string): string | undefined {
  const q = text.match(REASON_QUOTED_RE);
  if (q && q[1] !== undefined) return q[1];
  const b = text.match(REASON_BARE_RE);
  if (b && b[1]) return b[1];
  return undefined;
}

export function parseSuppressions(content: string, options: ParseSuppressOptions = {}): SuppressMap {
  const now = options.now ?? new Date();
  const perLine = new Map<number, SuppressEntry[]>();
  const fileWide: SuppressEntry[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    PRAGMA_RE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = PRAGMA_RE.exec(line)) !== null) {
      const directive = match[1];
      const rest = match[2] ?? '';
      const ids = rest.match(RULE_ID_RE);
      const expiresAt = parseUntil(rest);
      // Expired suppressions are silently dropped — the underlying finding
      // reappears automatically once the date passes.
      if (expiresAt && now.getTime() > expiresAt.getTime()) continue;
      const entry: SuppressEntry = {
        ruleIds: new Set(ids && ids.length > 0 ? ids : [WILDCARD]),
        ...(expiresAt ? { expiresAt } : {}),
        ...(parseReason(rest) !== undefined ? { reason: parseReason(rest) } : {}),
      };
      if (directive === 'disable-file') {
        fileWide.push(entry);
        continue;
      }
      const targetLine = directive === 'disable-line' ? i + 1 : i + 2;
      let bucket = perLine.get(targetLine);
      if (!bucket) {
        bucket = [];
        perLine.set(targetLine, bucket);
      }
      bucket.push(entry);
    }
  }

  return { perLine, fileWide };
}

/**
 * What one entry does to a finding of `severity` for `ruleId`.
 *
 * `blocked` is the D5 case: the entry matched only through its wildcard, and
 * the finding carries a security judgement, so the suppression is refused. The
 * three-way result exists because "refused" and "did not match" have to stay
 * distinguishable — the caller reports the first as an audit event on a finding
 * it keeps, and the second not at all.
 */
type Coverage = 'no' | 'covers' | 'blocked';

function entryCovers(entry: SuppressEntry, ruleId: string, severity: Severity): Coverage {
  // Naming the rule is always honoured, at every severity. This is the escape
  // hatch, and it is deliberately the *only* one: no flag, no config key, no
  // "force" pragma. A team that genuinely accepts a specific critical finding
  // writes down which one, which turns a blanket silence into a reviewable
  // statement about a known rule. The quick-fix action the VS Code extension
  // offers already emits this form (`disable-next-line <ruleId>`), so the
  // ordinary interactive path is unaffected by the gate below.
  if (entry.ruleIds.has(ruleId)) return 'covers';
  if (!entry.ruleIds.has(WILDCARD)) return 'no';
  // Wildcard. It keeps full authority over the advisory bands and loses it over
  // the ones that carry a security verdict — see SECURITY_JUDGEMENT_SEVERITIES.
  return isSecurityJudgementSeverity(severity) ? 'blocked' : 'covers';
}

/**
 * The outcome of consulting every suppression entry that could apply.
 *
 * `overridden` is only ever set when `suppressed` is false: if any entry
 * legitimately covers the finding it is gone, and a refusal recorded on a
 * finding nobody will see would be noise. It carries the *first* refused entry
 * rather than all of them, matching how `suppressed` short-circuits — one
 * refusal is the whole signal, and a file that stacks five blanket pragmas is
 * not five times as interesting.
 */
export interface SuppressionDecision {
  suppressed: boolean;
  overridden?: SuppressionOverride;
  /**
   * Which scope actually did the suppressing. Set if and only if `suppressed` is
   * true, so the caller can record WHAT silenced the finding without re-deriving
   * it (D8 observability). It sits on the decision rather than being inferred at
   * the call site because the call site cannot tell `file` from `line` after the
   * fact — the two scopes are resolved in separate loops in here and the loser
   * leaves no trace.
   */
  scope?: SuppressionScope;
}

/**
 * Resolve every pragma that could apply to a finding for `ruleId` at `line`.
 *
 * Both scopes are gated, not just the file-wide one. Gating `disable-file`
 * alone would leave the identical attack one line longer: a bare
 * `// vibeguard:disable-line` sitting on the vulnerable line is the same
 * blanket silence with a smaller blast radius, and it is the form the editor
 * quick-fix trains people to reach for.
 */
export function evaluateSuppression(
  map: SuppressMap,
  ruleId: string,
  line: number | undefined,
  severity: Severity,
): SuppressionDecision {
  let overridden: SuppressionOverride | undefined;
  for (const e of map.fileWide) {
    const c = entryCovers(e, ruleId, severity);
    if (c === 'covers') return { suppressed: true, scope: 'file' };
    if (c === 'blocked' && !overridden) {
      overridden = { channel: 'pragma', scope: 'file', ...(e.reason !== undefined ? { reason: e.reason } : {}) };
    }
  }
  const bucket = line == null ? undefined : map.perLine.get(line);
  for (const e of bucket ?? []) {
    const c = entryCovers(e, ruleId, severity);
    if (c === 'covers') return { suppressed: true, scope: 'line' };
    if (c === 'blocked' && !overridden) {
      overridden = { channel: 'pragma', scope: 'line', ...(e.reason !== undefined ? { reason: e.reason } : {}) };
    }
  }
  return { suppressed: false, ...(overridden ? { overridden } : {}) };
}

/**
 * Returns true if a finding for `ruleId` at `line` should be dropped.
 *
 * `severity` is required rather than optional on purpose: an optional parameter
 * would let an un-updated call site keep compiling and silently opt out of the
 * gate, which is the one failure mode this change cannot afford.
 */
export function isSuppressed(
  map: SuppressMap,
  ruleId: string,
  line: number | undefined,
  severity: Severity,
): boolean {
  return evaluateSuppression(map, ruleId, line, severity).suppressed;
}

/**
 * D8 accounting. Everything below is OBSERVABILITY, not defence: it changes what
 * a scan reports about suppressions it has already honoured, and never whether
 * one is honoured. See `SuppressionRecord` in @vibeguard/findings-schema.
 *
 * The accumulator is shared rather than reimplemented per call site because
 * there are three enforcement points (the analyzer's pragma gate, plus the
 * config gate in `scanPath` and in `scanDiff`) and they have to agree on the
 * aggregation key exactly, or the same suppression will be counted as two
 * different rows depending on which entry point the user came through.
 */
export type SuppressionTally = Map<string, SuppressionRecord>;

/** The identity of a row: same rule, same channel, same scope, same file. */
function tallyKey(channel: SuppressionChannel, scope: SuppressionScope, ruleId: string, filePath?: string): string {
  return `${channel}|${scope}|${ruleId}|${filePath ?? ''}`;
}

/**
 * Record `count` suppressed findings. Call it at the point the finding is
 * dropped — the `continue`, not somewhere that re-derives the decision — so a
 * row can only exist if something really was removed.
 */
export function tallySuppression(
  into: SuppressionTally,
  entry: { channel: SuppressionChannel; scope: SuppressionScope; ruleId: string; filePath?: string },
  count = 1,
): void {
  const key = tallyKey(entry.channel, entry.scope, entry.ruleId, entry.filePath);
  const existing = into.get(key);
  if (existing) {
    existing.count += count;
    return;
  }
  into.set(key, {
    ruleId: entry.ruleId,
    channel: entry.channel,
    scope: entry.scope,
    ...(entry.filePath !== undefined ? { filePath: entry.filePath } : {}),
    count,
  });
}

/**
 * Fold a sub-scan's records into a walk-wide tally.
 *
 * This is the merge point the directory and diff walkers need: the analyzer
 * reports the PRAGMA suppressions of one file, and the walker adds its own
 * CONFIG suppressions on top, for every file. Without this the pragma half would
 * be silently discarded the moment a scan covered more than one file — the
 * per-file `ScanResponse` is thrown away by the walkers, and only `findings`,
 * `ruleErrors` and `degradations` were being carried across.
 */
export function mergeSuppressions(into: SuppressionTally, records: SuppressionRecord[] | undefined): void {
  for (const r of records ?? []) {
    tallySuppression(
      into,
      { channel: r.channel, scope: r.scope, ruleId: r.ruleId, ...(r.filePath !== undefined ? { filePath: r.filePath } : {}) },
      r.count,
    );
  }
}

/**
 * Materialise the tally for a `ScanResponse`, ordered so two runs over the same
 * input produce byte-identical output (the walkers iterate a directory listing,
 * and Map insertion order would otherwise leak that ordering into the artifact).
 * Sorted loudest-first — most suppressions is the row a reviewer wants at the
 * top — then by file and rule for a stable tie-break.
 */
export function collectSuppressions(tally: SuppressionTally): SuppressionRecord[] {
  return [...tally.values()].sort((a, b) => {
    if (a.count !== b.count) return b.count - a.count;
    const fa = a.filePath ?? '';
    const fb = b.filePath ?? '';
    if (fa !== fb) return fa < fb ? -1 : 1;
    if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
    if (a.channel !== b.channel) return a.channel < b.channel ? -1 : 1;
    return a.scope < b.scope ? -1 : a.scope > b.scope ? 1 : 0;
  });
}

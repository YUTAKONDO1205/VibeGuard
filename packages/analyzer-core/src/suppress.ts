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

import { isSecurityJudgementSeverity, type Severity, type SuppressionOverride } from '@vibeguard/findings-schema';

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
    if (c === 'covers') return { suppressed: true };
    if (c === 'blocked' && !overridden) {
      overridden = { channel: 'pragma', scope: 'file', ...(e.reason !== undefined ? { reason: e.reason } : {}) };
    }
  }
  const bucket = line == null ? undefined : map.perLine.get(line);
  for (const e of bucket ?? []) {
    const c = entryCovers(e, ruleId, severity);
    if (c === 'covers') return { suppressed: true };
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

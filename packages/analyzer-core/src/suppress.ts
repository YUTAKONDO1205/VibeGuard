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
 */

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

function entryCovers(entry: SuppressEntry, ruleId: string): boolean {
  return entry.ruleIds.has(WILDCARD) || entry.ruleIds.has(ruleId);
}

/** Returns true if a finding for `ruleId` at `line` should be dropped. */
export function isSuppressed(map: SuppressMap, ruleId: string, line: number | undefined): boolean {
  for (const e of map.fileWide) {
    if (entryCovers(e, ruleId)) return true;
  }
  if (line == null) return false;
  const bucket = map.perLine.get(line);
  if (!bucket) return false;
  for (const e of bucket) {
    if (entryCovers(e, ruleId)) return true;
  }
  return false;
}

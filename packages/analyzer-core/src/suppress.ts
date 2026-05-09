/**
 * Suppress-comment parsing.
 *
 * Recognised pragmas (case-sensitive):
 *   vibeguard:disable-line       — suppress findings on this line
 *   vibeguard:disable-next-line  — suppress findings on the following line
 *   vibeguard:disable-file       — suppress findings for the entire file
 *
 * Each pragma may optionally be followed by one or more rule IDs
 * (e.g. `VG-INJ-004`). When IDs are listed, only those rules are suppressed;
 * with no IDs, every rule is suppressed for that scope.
 *
 * Examples:
 *   eval(payload); // vibeguard:disable-line VG-INJ-004
 *   // vibeguard:disable-next-line
 *   exec(userInput);
 *   // vibeguard:disable-file VG-AUTH-003 VG-AUTH-004
 */

const PRAGMA_RE = /vibeguard:(disable-line|disable-next-line|disable-file)\b([^\n\r]*)/g;
const RULE_ID_RE = /VG-[A-Z]+-\d+/g;
const WILDCARD = '*';

export interface SuppressMap {
  /** 1-based line number → set of suppressed rule IDs (or '*' for all). */
  perLine: Map<number, Set<string>>;
  /** Rule IDs (or '*') suppressed for the whole file. */
  fileWide: Set<string>;
}

export function parseSuppressions(content: string): SuppressMap {
  const perLine = new Map<number, Set<string>>();
  const fileWide = new Set<string>();
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    PRAGMA_RE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = PRAGMA_RE.exec(line)) !== null) {
      const directive = match[1];
      const rest = match[2] ?? '';
      const ids = rest.match(RULE_ID_RE) ?? [WILDCARD];
      if (directive === 'disable-file') {
        for (const id of ids) fileWide.add(id);
        continue;
      }
      const targetLine = directive === 'disable-line' ? i + 1 : i + 2;
      let bucket = perLine.get(targetLine);
      if (!bucket) {
        bucket = new Set<string>();
        perLine.set(targetLine, bucket);
      }
      for (const id of ids) bucket.add(id);
    }
  }

  return { perLine, fileWide };
}

/** Returns true if a finding for `ruleId` at `line` should be dropped. */
export function isSuppressed(map: SuppressMap, ruleId: string, line: number | undefined): boolean {
  if (map.fileWide.has(WILDCARD) || map.fileWide.has(ruleId)) return true;
  if (line == null) return false;
  const bucket = map.perLine.get(line);
  if (!bucket) return false;
  return bucket.has(WILDCARD) || bucket.has(ruleId);
}

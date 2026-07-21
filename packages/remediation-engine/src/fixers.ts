import type { RuleMatch } from '@vibeguard/rules';

// VG-EMB 18 FIX — deterministic, LLM-free, zero-send autofix.
//
// A fixer table keyed by rule ID, DELIBERATELY separate from RuleDefinition:
//   - the rules package is the detection core shipped to all four channels; the
//     Chrome / VS Code bundles do not need fix code.
//   - one file enumerates exactly which rules are auto-fixable — auditable at a
//     glance.
//   - no findings-schema / RuleDefinition churn.
// The drift risk (a stale ruleId key) is closed by fixers.test.ts, which asserts
// every key here exists in `allRules`.
//
// THE DESIGN PRINCIPLE, one line: a fixer's `build` returns edits ONLY when the
// fix is deterministically correct from the file bytes alone, and `null`
// otherwise. It never invents data the code does not contain (a buffer size, a
// certificate, a credential) and never changes a signature. Fixes that would
// require any of that carry NO fixer — prose remediation only.
//
// `safety`:
//   - 'safe'         : strictly-stronger semantics, applyable without review.
//   - 'needs-review' : correct and fail-closed, but changes behaviour (a TLS
//                      handshake starts validating, a bypass turns off) — a human
//                      must confirm the intent.

/** A single text replacement, as absolute character offsets into the file. */
export interface FixEdit {
  start: number;
  end: number;
  replacement: string;
}

export interface Fixer {
  /** Imperative title shown in the PR / diff. */
  title: string;
  safety: 'safe' | 'needs-review';
  /** Edits for this match, or null when the fix is not provably correct here. */
  build(content: string, match: RuleMatch): FixEdit[] | null;
}

/** Absolute offset of the start of 1-based `line`. */
function lineStartOffset(content: string, line: number): number {
  let off = 0;
  for (let l = 1; l < line; l++) {
    const nl = content.indexOf('\n', off);
    if (nl === -1) return content.length;
    off = nl + 1;
  }
  return off;
}

/** The physical line (without terminator) containing `startLine`, and its offset. */
function lineOf(content: string, match: RuleMatch): { text: string; offset: number } {
  const offset = lineStartOffset(content, match.startLine);
  const nl = content.indexOf('\n', offset);
  const end = nl === -1 ? content.length : nl;
  return { text: content.slice(offset, end), offset };
}

/** Build a single-token replacement from a regex whose group 1 is the token. */
function tokenSwap(
  content: string,
  match: RuleMatch,
  re: RegExp,
  replacement: string,
): FixEdit[] | null {
  const { text, offset } = lineOf(content, match);
  // Seed the search at the finding's COLUMN, not the line start, so a line with
  // two matching tokens (`a("http://x"); b("http://y");`) fixes the one the
  // finding actually anchors to — not always the first.
  const col0 = Math.max(0, (match.startColumn ?? 1) - 1);
  const sub = text.slice(col0);
  const m = re.exec(sub);
  if (!m || m.index === undefined) return null;
  // Offset of group 1 within the searched substring.
  const g1 = m[1]!;
  const g1Local = sub.indexOf(g1, m.index);
  if (g1Local === -1) return null;
  const start = offset + col0 + g1Local;
  return [{ start, end: start + g1.length, replacement }];
}

export const fixers: Record<string, Fixer> = {
  // #define DEBUG 1 → #define DEBUG 0. Strictly-stronger: turns debug OFF.
  'VG-EMB-020': {
    title: 'Set the debug define to 0',
    safety: 'safe',
    build: (content, match) =>
      tokenSwap(
        content,
        match,
        /#[ \t]*define[ \t]+(?:DEBUG|DEBUG_MODE|ENABLE_DEBUG|DEBUG_ENABLED|VERBOSE(?:_DEBUG)?)[ \t]+(1|true|TRUE)\b/,
        '0',
      ),
  },

  // #define BYPASS_AUTH 1 → 0. Fail-closed but behaviour-changing (the bypass
  // stops working, which is the point). The `if (BYPASS_...)` runtime form has
  // no safe token to flip, so build returns null there.
  'VG-EMB-021': {
    title: 'Turn the bypass flag off',
    safety: 'needs-review',
    build: (content, match) =>
      tokenSwap(
        content,
        match,
        /#[ \t]*define[ \t]+(?:BYPASS|SKIP|DISABLE)_(?:AUTH|LOGIN|SECURITY|VERIFY|TLS|SSL)\w*[ \t]+(1|true)\b/,
        '0',
      ),
  },

  // MBEDTLS_SSL_VERIFY_NONE → MBEDTLS_SSL_VERIFY_REQUIRED. The setInsecure() /
  // skip_cert_common_name_check alternatives of VG-EMB-011 have no clean token
  // swap (they need a CA to be installed), so build returns null for them.
  'VG-EMB-011': {
    title: 'Require certificate verification',
    safety: 'needs-review',
    build: (content, match) =>
      tokenSwap(content, match, /(MBEDTLS_SSL_VERIFY_NONE)/, 'MBEDTLS_SSL_VERIFY_REQUIRED'),
  },

  // "http://…" → "https://…". Behaviour-changing: the endpoint must serve TLS
  // and the device must trust its CA, hence needs-review, not safe.
  'VG-EMB-010': {
    title: 'Use https for the endpoint',
    safety: 'needs-review',
    build: (content, match) => tokenSwap(content, match, /"(http):\/\//, 'https'),
  },

  // O_DIRECT → O_DIRECT | O_SYNC. Adds durability; a perf change, so review.
  'VG-RTOS-004': {
    title: 'Add O_SYNC for durability',
    safety: 'needs-review',
    build: (content, match) => {
      // Idempotence guard: if the flags already contain O_SYNC/O_DSYNC, there is
      // nothing to add — never append a second one.
      if (/O_SYNC|O_DSYNC/.test(lineOf(content, match).text)) return null;
      return tokenSwap(content, match, /(O_DIRECT)\b/, 'O_DIRECT | O_SYNC');
    },
  },
};

/** Build the fix for one finding, or null when this rule/match is not fixable. */
export function buildFix(
  ruleId: string,
  content: string,
  match: RuleMatch,
): { title: string; safety: Fixer['safety']; edits: FixEdit[] } | null {
  const fixer = fixers[ruleId];
  if (!fixer) return null;
  const edits = fixer.build(content, match);
  if (!edits || edits.length === 0) return null;
  return { title: fixer.title, safety: fixer.safety, edits };
}

/**
 * Apply edits to content. Bottom-up (edits sorted by start descending) so
 * earlier offsets stay valid. Returns null and applies NOTHING if any two edits
 * overlap — never a partial apply, which could corrupt the file.
 */
export function applyFixes(content: string, edits: FixEdit[]): string | null {
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  for (let i = 1; i < sorted.length; i++) {
    // sorted descending: the previous (higher) edit must start at or after this
    // edit's end, or they overlap.
    if (sorted[i]!.end > sorted[i - 1]!.start) return null;
  }
  let out = content;
  for (const e of sorted) {
    out = out.slice(0, e.start) + e.replacement + out.slice(e.end);
  }
  return out;
}

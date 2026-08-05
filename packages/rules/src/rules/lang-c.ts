// vibeguard:disable-file VG-MEM-002
// This file DEFINES the C/C++ memory rules; the literal tokens (`strcpy(`,
// `sprintf(`, `gets(`, `free(`) appear inside regex sources and remediation
// prose by design, so the file must not flag itself.
//
// VG-EMB 17d EMB-MEM — the C/C++ memory / pointer family (languages ['c','cpp']).
//
// HONESTY, STATED UP FRONT: this family has NO novelty. flawfinder, cppcheck,
// clang-tidy and every MISRA checker have covered `strcpy`/`gets`/unchecked
// copies for years. It exists so VibeGuard is not EMPTY when it first looks at
// embedded C — a floor, not a contribution, and not the headline. The
// genuinely embedded-specific, existing-tool-invisible detections live in
// embedded-ai.ts (17e) and embedded-rtos.ts (17f).
//
// WHAT IS DELIBERATELY NOT HERE (regex cannot decide these without dataflow, and
// forcing them lexically manufactures exactly the false positives the E3=0
// invariant forbids):
//   - Whether a `memcpy` destination is large enough (needs the dst size).
//   - Use-after-free / double-free ACROSS control flow (needs a flow graph).
//     MEM-004/005 below detect ONLY the same-block, straight-line shape and say
//     so; anything crossing a `}`/`return`/`goto`/reassignment is out of scope.
//   - Integer overflow before a `malloc`, format-string bugs beyond `sprintf`.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  runRegex,
  indexToPosition,
  isCommentLine,
  blankCommentsAndStrings,
  REGEX_INPUT_CAP,
  REGEX_MATCH_LIMIT,
} from '../matcher-utils.js';

export const cGets: RuleDefinition = {
  ruleId: 'VG-MEM-001',
  name: 'gets() — unbounded stack read',
  description:
    'gets() reads an unbounded line into a fixed buffer and cannot be used safely; it was removed from C11 for this reason.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-242', 'CWE-120'],
  tags: ['embedded', 'memory-safety'],
  remediation: {
    why: 'gets() has no length argument, so any input longer than the buffer overflows the stack. There is no safe call.',
    how: 'Use fgets(buf, sizeof(buf), stdin), which bounds the read to the buffer size.',
    exampleFix: 'fgets(buf, sizeof(buf), stdin);',
  },
  // Lookbehind excludes `fgets`, `obj.gets(`, `p->gets(`. Single bounded run.
  // Run over comment/string-blanked text so `/* gets(buf) banned */` and
  // `"use gets"` do not fire — block comments are the dominant C comment style
  // and `skipCommentLines` only knows `//`.
  match: (ctx) =>
    runRegex(blankCommentsAndStrings(ctx.content, ctx.language), /(?<![\w.>])gets[ \t]{0,8}\(/g, {
      skipCommentLines: true,
      language: ctx.language,
    }),
};

export const cUnboundedCopy: RuleDefinition = {
  ruleId: 'VG-MEM-002',
  name: 'Unbounded string copy (strcpy / strcat / sprintf)',
  description:
    'strcpy / strcat / sprintf / vsprintf write without a destination-size bound. With attacker-influenced input this overflows the destination.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-120', 'CWE-787'],
  tags: ['embedded', 'memory-safety', 'ai-prone'],
  remediation: {
    why: 'None of these take a destination size, so a source longer than the destination overflows it. On an MCU with no MMU this silently corrupts adjacent memory.',
    how: 'Use the size-bounded forms: strncpy / strncat with an explicit length, or snprintf(dst, sizeof(dst), ...). Always reserve room for the terminating NUL.',
    exampleFix: 'snprintf(dst, sizeof(dst), "%s", src);',
  },
  // `strncpy`/`snprintf` are not substrings of these tokens, so no exclusion is
  // needed. Run over comment/string-blanked text so the token inside a comment
  // or string literal (`/* strcpy(...) */`, `"use strcpy"`) does not fire.
  match: (ctx) =>
    runRegex(
      blankCommentsAndStrings(ctx.content, ctx.language),
      /(?<![\w.>])(?:strcpy|strcat|sprintf|vsprintf)[ \t]{0,8}\(/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const cMemcpyFromStrlen: RuleDefinition = {
  ruleId: 'VG-MEM-003',
  name: 'memcpy / memmove sized from the source (strlen)',
  description:
    'A memcpy/memmove whose length comes from strlen() of the source copies as many bytes as the source holds, not as many as the destination can take — a classic off-by-one / overflow when the destination is smaller.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-120'],
  tags: ['embedded', 'memory-safety'],
  remediation: {
    why: 'Sizing the copy from the source ignores the destination capacity. strlen also omits the NUL terminator, so a following NUL write can overflow by one.',
    how: 'Bound the length to the destination: memcpy(dst, src, min(sizeof(dst), strlen(src) + 1)), or use a length that is known to fit dst.',
  },
  // Lazy, bounded gap then the literal `strlen` — no two variable runs adjacent,
  // so the D3 ReDoS invariant holds. Single-line only (`[^;\n]`); multi-line
  // calls are a declared miss.
  match: (ctx) =>
    runRegex(
      blankCommentsAndStrings(ctx.content, ctx.language),
      /(?<![\w.>])mem(?:cpy|move)[ \t]{0,8}\([^;\n]{0,160}?\bstrlen[ \t]{0,8}\(/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

/**
 * Shared straight-line free-pair scan for MEM-004 (double-free) and MEM-005
 * (use-after-free). Deliberately conservative: it reasons only within a single
 * straight-line window and BAILS on the first sign of control flow, because a
 * regex cannot see the flow graph and a guess in this space is the exact false
 * positive E3=0 forbids (`if (err) { free(x); return; } … free(x);` is correct).
 *
 * Linear: `free(...)` sites are capped by REGEX_MATCH_LIMIT, the between-windows
 * are disjoint per pointer, and each check is `includes` plus one bounded regex.
 */
interface FreeSite {
  ptr: string;
  /** Offset of the `free` token. */
  start: number;
  /** Offset one past the closing paren. */
  end: number;
  line: number;
  column: number;
}

// A window terminates at the first sign the two statements are not on one
// straight-line path: a block boundary, either arm of a branch, a jump, or a
// ternary. `else` is here so `if (a) free(p); else free(p);` — mutually
// exclusive arms — does not read as a double free.
const FLOW_BARRIER = /[{}]|\breturn\b|\bgoto\b|\bbreak\b|\bcontinue\b|\belse\b|\?/;

// The farthest apart two frees of one pointer may sit and still be treated as a
// single straight-line window. Bounds the pair-scan to linear time (without it,
// N pointers each scanning a long barrier-free span is O(N·n)); a real
// straight-line double free is a handful of lines, never kilobytes, apart.
const MAX_PAIR_GAP = 2_000;

function scanFreeSites(ctx: { content: string; lines: string[]; language?: string }): {
  scanText: string;
  frees: FreeSite[];
} {
  const raw =
    ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
  // Scan over comment- and string-blanked text so a `free`/deref inside a
  // comment (`/* free(p) old *\/`) or a string (`"p->x"`) is not a match.
  // Length-preserving, so offsets and lines still refer to the original.
  const scanText = blankCommentsAndStrings(raw, ctx.language);
  const freeRe = /(?<![\w.>])free[ \t]{0,8}\([ \t]{0,8}(\w{1,40})[ \t]{0,8}\)/g;
  const frees: FreeSite[] = [];
  let m: RegExpExecArray | null;
  while ((m = freeRe.exec(scanText)) !== null && frees.length < REGEX_MATCH_LIMIT) {
    const pos = indexToPosition(scanText, m.index);
    if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
    frees.push({
      ptr: m[1]!,
      start: m.index,
      end: m.index + m[0].length,
      line: pos.line,
      column: pos.column,
    });
  }
  return { scanText, frees };
}

export const cDoubleFree: RuleDefinition = {
  ruleId: 'VG-MEM-004',
  name: 'Double free on the same pointer (straight-line)',
  description:
    'The same pointer is passed to free() twice with no reassignment and no control flow between the calls. SAME-BLOCK STRAIGHT-LINE ONLY — anything across a branch, loop, or return is out of scope for a lexical scan.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'high',
  defaultConfidence: 'low',
  cwe: ['CWE-415'],
  tags: ['embedded', 'memory-safety'],
  remediation: {
    why: 'Freeing an already-freed pointer corrupts the allocator; on many MCU allocators it is exploitable or a hard fault.',
    how: 'Free once, then set the pointer to NULL (free(x); x = NULL;). free(NULL) is a safe no-op, so the second free becomes harmless.',
    exampleFix: 'free(x); x = NULL;',
  },
  match: (ctx) => {
    const { scanText, frees } = scanFreeSites(ctx);
    const byPtr = new Map<string, FreeSite[]>();
    for (const f of frees) {
      const list = byPtr.get(f.ptr) ?? [];
      list.push(f);
      byPtr.set(f.ptr, list);
    }
    const out: RuleMatch[] = [];
    for (const [ptr, list] of byPtr) {
      // `ptr` is `\w{1,40}` — no regex metacharacters, safe to interpolate.
      const reassign = new RegExp(`\\b${ptr}[ \\t]{0,8}=[^=]`);
      for (let i = 1; i < list.length; i++) {
        if (list[i]!.start - list[i - 1]!.end > MAX_PAIR_GAP) continue;
        const between = scanText.slice(list[i - 1]!.end, list[i]!.start);
        if (FLOW_BARRIER.test(between) || reassign.test(between)) continue;
        const cur = list[i]!;
        out.push({
          startLine: cur.line,
          endLine: cur.line,
          startColumn: cur.column,
          endColumn: cur.column + 4,
          evidence: `free(${ptr})`,
        });
      }
    }
    return out;
  },
};

export const cUseAfterFree: RuleDefinition = {
  ruleId: 'VG-MEM-005',
  name: 'Use after free (straight-line)',
  description:
    'A pointer is dereferenced after free() with no reassignment and no control flow between. SAME-BLOCK STRAIGHT-LINE ONLY — the safe idiom free(x); x = NULL; ends the window before anything is flagged.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'high',
  defaultConfidence: 'low',
  cwe: ['CWE-416'],
  tags: ['embedded', 'memory-safety'],
  remediation: {
    why: 'Reading or writing through a freed pointer is undefined behaviour and a common exploitation primitive.',
    how: 'Set the pointer to NULL immediately after free() and re-check before use, or restructure so the pointer is not touched after being freed.',
    exampleFix: 'free(x); x = NULL;',
  },
  match: (ctx) => {
    const { scanText, frees } = scanFreeSites(ctx);
    const out: RuleMatch[] = [];
    for (const f of frees) {
      // `ptr` is `\w{1,40}` — safe to interpolate.
      const ptr = f.ptr;
      // The window runs from just after this free() to the first flow barrier,
      // reassignment, or NULL-out of the pointer.
      const rest = scanText.slice(f.end, f.end + 400);
      const barrier = rest.search(FLOW_BARRIER);
      const nulled = rest.search(new RegExp(`\\b${ptr}[ \\t]{0,8}=`));
      let windowEnd = rest.length;
      if (barrier !== -1) windowEnd = Math.min(windowEnd, barrier);
      if (nulled !== -1) windowEnd = Math.min(windowEnd, nulled);
      const window = rest.slice(0, windowEnd);
      // A dereference of the freed pointer: `x->`, `*x`, or `x[`.
      const deref = new RegExp(`\\b${ptr}[ \\t]{0,8}(?:->|\\[)|\\*[ \\t]{0,8}${ptr}\\b`);
      const rel = window.search(deref);
      if (rel === -1) continue;
      const pos = indexToPosition(scanText, f.end + rel);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + ptr.length,
        evidence: `use of ${ptr} after free`,
      });
    }
    return out;
  },
};

/**
 * The words that make an identifier read as "this holds a secret". Matched
 * against the SPLIT identifier, never as substrings: `monkey` is one word and is
 * not `key`, `keyboard` is not `key`, but `session_key`, `sessionKey` and
 * `ctx->authToken` all split to a word that is in this set.
 */
const SECRET_WORDS = new Set([
  'secret',
  'secrets',
  'password',
  'passwd',
  'passphrase',
  'privkey',
  'key',
  'keys',
  'token',
  'tokens',
  'credential',
  'credentials',
  'creds',
  'apikey',
]);

/** `ctx->session_key` / `sessionKey` / `s.apiKey[0]` -> ['ctx','session','key'] … */
function identifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word.length > 0)
    .map((word) => word.toLowerCase());
}

function namesASecret(identifier: string): boolean {
  return identifierWords(identifier).some((word) => SECRET_WORDS.has(word));
}

/**
 * VG-MEM-006 — a secret-named buffer cleared with a plain `memset`.
 *
 * WHY A LEXICAL RULE CAN SAY SOMETHING TRUE HERE, when it usually cannot about
 * memory: this is not a claim about whether the buffer is large enough or
 * whether the pointer is live. It is a claim about the WIPE IDIOM. The last
 * write to storage that is never read again is a dead store, and dead-store
 * elimination is permitted to delete it — so the clear that the source performs
 * may be absent from the object file. That is CWE-14, and it does not need
 * dataflow to name: `memset` is removable, `explicit_bzero` is not.
 *
 * SCOPE, deliberately narrow (E3=0 is the constraint that shapes this):
 *   - Only `memset(<secret-named>, 0, …)`. A wipe with a non-zero fill is not
 *     the idiom, and a non-secret-named buffer is not this rule's business —
 *     `memset(buf, 0, sizeof(buf))` on a scratch buffer is ordinary code and
 *     stays silent. `samples/crossfile-fixtures/embedded-real-api/main.c`
 *     contains exactly that line and is the standing negative control.
 *   - `memset(secret, '\0', n)` is NOT matched: the character literal is blanked
 *     with strings before the scan. A known, accepted false negative.
 *   - Whether the compiler ACTUALLY removed the store is not decidable here and
 *     is not claimed. The finding is about depending on a removable wipe.
 */
export const cInsecureSecretWipe: RuleDefinition = {
  ruleId: 'VG-MEM-006',
  name: 'Secret buffer cleared with a removable memset',
  description:
    'memset(..., 0, ...) on a buffer whose name says it holds a secret. A final write that is never read again is a dead store, and optimising compilers delete dead stores, so the wipe can be missing from the shipped binary while the source still shows it.',
  languages: ['c', 'cpp'],
  category: 'memory',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-14', 'CWE-226'],
  tags: ['embedded', 'memory-safety'],
  remediation: {
    why: 'Clearing a buffer that is never read afterwards is a dead store the compiler may remove. The secret then remains in memory past the line that appears to erase it — the source and the binary disagree, and only the binary runs.',
    how: 'Use a wipe the compiler is not allowed to elide: explicit_bzero() (glibc/BSD), memset_s() (C11 Annex K), or SecureZeroMemory() (Windows).',
    exampleFix: 'explicit_bzero(secret, sizeof(secret));',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    // Length-preserving blanking, so offsets and line numbers still address the
    // original text: `/* memset(secret, 0, n) */` and `"memset(key, 0, n)"` are
    // not code and must not fire.
    const scanText = blankCommentsAndStrings(raw, ctx.language);
    // One bounded run per element and no two variable-length runs adjacent (the
    // optional `&` group opens with a literal, so a space is never ambiguous
    // between two quantifiers). Linear, per the L1 rewrite rule.
    const wipeRe =
      /(?<![\w.>])memset[ \t]{0,8}\([ \t]{0,8}(?:&[ \t]{0,8})?([A-Za-z_][A-Za-z0-9_.>[\]-]{0,60})[ \t]{0,8},[ \t]{0,8}0(?:x0{1,2})?[ \t]{0,8},/g;
    const out: RuleMatch[] = [];
    let m: RegExpExecArray | null;
    while ((m = wipeRe.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      const target = m[1]!;
      if (!namesASecret(target)) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + m[0].length,
        evidence: `memset(${target}, 0, ...)`,
      });
    }
    return out;
  },
};

export const cRules: RuleDefinition[] = [
  cGets,
  cUnboundedCopy,
  cMemcpyFromStrlen,
  cDoubleFree,
  cUseAfterFree,
  cInsecureSecretWipe,
];

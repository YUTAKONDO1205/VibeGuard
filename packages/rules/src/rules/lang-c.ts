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

/**
 * A second tier of secret words, each paired with the words that argue it is NOT
 * a secret in this identifier.
 *
 * WHY A SECOND TIER RATHER THAN MORE ENTRIES IN SECRET_WORDS. The words above are
 * unambiguous: nothing called `password` is not a password. These are not. `seed`
 * is a secret in a wallet and a nuisance in `srand`; `pin` is a secret on a keypad
 * and a GPIO number in every embedded file this rule is meant to read; `sk` is a
 * signing key in crypto code and a socket in kernel code. Putting them in the
 * first tier would trade the E3=0 invariant for recall, which is the trade this
 * family exists not to make.
 *
 * So they fire, but with two brakes: a veto list checked against the OTHER words
 * of the same identifier, and `confidence: 'low'` on the match, so a reader who
 * has decided this rule may only speak when sure can filter them out with
 * `--min-confidence medium` and get exactly the previous behaviour back.
 *
 * The vocabulary is not guesswork. It is the set of identifiers that a measured
 * corpus of AI-generated C actually used for a secret and this rule silently
 * missed; see `compiler/eval/ai-generated/`. `buf` and `buffer` appear in that
 * corpus too and are deliberately NOT here — `samples/crossfile-fixtures/
 * embedded-real-api/main.c` wipes a scratch buffer called `buf` and is the
 * standing negative control for this rule.
 */
interface TierBWord {
  /** Words in the SAME identifier that argue this is not a secret. */
  readonly veto: ReadonlySet<string>;
  /**
   * Also require the FILE to look like it handles secrets.
   *
   * Only for a word whose collision is with a different domain entirely AND whose
   * commonest spelling offers no sibling to veto. `sk` is the case: kernel code
   * writes a bare `sk` for a socket and control code writes `Sk` for the Kalman
   * innovation covariance, and neither has a second word to test. `pin` and
   * `seed` do not need this — embedded and PRNG code qualifies them (`relay_pin`,
   * `xorshift_seed`), so the veto list reaches them, and requiring crypto
   * vocabulary would silence the keypad file that is precisely the target.
   */
  readonly needsSecretContext?: boolean;
}

const SECRET_WORDS_TIER_B = new Map<string, TierBWord>([
  [
    'seed',
    { veto: new Set([
      // PRNG families, spelled the way each library spells them.
      'rand', 'random', 'srand', 'prng', 'rng', 'mt', 'mersenne', 'twister',
      'xorshift', 'xoshiro', 'xoroshiro', 'pcg', 'lcg', 'splitmix', 'wyhash',
      'hash', 'noise', 'perlin', 'simplex',
      // "seed" as a starting point: region growing, flood fill, BFS.
      'fill', 'flood', 'grow', 'growth', 'region', 'bfs', 'dfs', 'queue', 'stack',
      // non-crypto qualifiers
      'world', 'sim', 'tile', 'chunk', 'worker', 'test', 'demo',
    ]) },
  ],
  [
    'pin',
    { veto: new Set([
      // attribute words
      'gpio', 'led', 'pwm', 'adc', 'dac', 'mux', 'irq', 'port', 'mask', 'map',
      'mode', 'dir', 'config', 'cfg', 'num', 'no', 'index', 'idx', 'state', 'level',
      'bit', 'reg', 'register', 'assign', 'assignment', 'default', 'init',
      // device words: what embedded code qualifies a physical pin with
      'relay', 'row', 'col', 'column', 'scan', 'channel', 'sensor', 'button',
      'switch', 'motor', 'servo', 'spi', 'uart', 'i2c', 'can', 'header', 'board',
      'table', 'list', 'array', 'drive', 'input', 'output', 'analog', 'digital',
    ]) },
  ],
  [
    'sk',
    {
      veto: new Set(['buf', 'buff', 'sock', 'socket', 'skb', 'net', 'conn', 'fd', 'list', 'queue', 'lock', 'prot']),
      needsSecretContext: true,
    },
  ],
  ['premaster', { veto: new Set() }],
  // `vkey` is NOT here. It is the Win32 name for the 256-byte virtual-key state
  // array that GetKeyboardState() fills — key-down bits, not a secret — and it
  // has no sibling word to veto, so it would fire on every input handler. It was
  // worth two detections across 720 generations. Not a trade worth making.
]);

/**
 * Does the FILE look like it handles secrets at all?
 *
 * The second tier needs this and the first tier does not. `password` means one
 * thing everywhere; `sk`, `pin` and `seed` mean a signing key, a keypad code and
 * a wallet phrase inside cryptographic code, and a socket, a GPIO number and an
 * RNG seed outside it. An identifier-local veto list cannot separate those,
 * because the commonest spellings have no sibling word to veto: kernel code
 * writes a bare `sk`, control code writes `Sk` for the Kalman innovation
 * covariance, and neither offers anything to test against.
 *
 * Only the words that need it are gated on this — see `needsSecretContext`.
 * Applying it to all of them was measured and rejected: it took recall on the
 * corpus from 96.9% to 66.0%, because a keypad file that wipes a `pin` has no
 * cryptographic vocabulary in it and is exactly the file this rule is for.
 *
 * This is a whole-file test, computed once per scan and not per match.
 */
// The boundaries are `[A-Za-z0-9]`, NOT `\b`. C identifiers join words with an
// underscore, and `_` is a word character, so `\bed25519\b` does not match inside
// `ed25519_sign` and `\bprivate_key\b` does not match inside
// `sign_with_private_key`. Anchoring on \b silently failed to find the context in
// every file that had it, which took the gate from selective to total.
const SECRET_CONTEXT_RE =
  /(?<![A-Za-z0-9])(?:crypto|cipher|encrypt|decrypt|chacha|poly1305|aes|rsa|ecdsa|eddsa|ed25519|curve25519|x25519|secp256|hmac|sha1|sha256|sha512|blake2|kdf|pbkdf2?|scrypt|argon2?|bcrypt|sodium|openssl|mbedtls|wolfssl|keypair|privkey|private|secret|password|passwd|passphrase|credential|token|wallet|mnemonic|totp|hotp|zeroize|explicit_bzero|memset_s|securezeromemory)(?![A-Za-z0-9])/i;

type SecretTier = 'named' | 'probable';

/**
 * Does this identifier name a secret, and how sure is the name alone?
 *
 * `null`  - no reason to think so; the rule stays silent.
 * `named` - a first-tier word. Reported at the rule's own confidence.
 * `probable` - a second-tier word, in a file that handles secrets, with no
 *   vetoing sibling. Reported at low confidence: the name is suggestive rather
 *   than decisive.
 */
function secretTier(identifier: string, fileHandlesSecrets: boolean): SecretTier | null {
  const words = identifierWords(identifier);
  if (words.some((word) => SECRET_WORDS.has(word))) return 'named';
  for (const word of words) {
    const entry = SECRET_WORDS_TIER_B.get(word);
    if (!entry) continue;
    if (entry.needsSecretContext && !fileHandlesSecrets) continue;
    // Vetoes are written singular; identifiers are not. `pin_state` and
    // `pin_states` are the same claim and must be vetoed alike.
    const vetoed = words.some(
      (other) => entry.veto.has(other) || (other.endsWith('s') && entry.veto.has(other.slice(0, -1))),
    );
    if (!vetoed) return 'probable';
  }
  return null;
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
 *   - Only `memset(<secret-named>, 0, …)`, where the argument may be taken by
 *     address (`&secret`) or converted (`(void *)secret`). A wipe with a
 *     non-zero fill is not the idiom, and a non-secret-named buffer is not this
 *     rule's business — `memset(buf, 0, sizeof(buf))` on a scratch buffer is
 *     ordinary code and stays silent. `samples/crossfile-fixtures/
 *     embedded-real-api/main.c` contains exactly that line and is the standing
 *     negative control.
 *   - The name test has two tiers. A first-tier word (`password`, `key`, …)
 *     reports at the rule's confidence. A second-tier word (`seed`, `pin`,
 *     `sk`, …) reports at LOW confidence and only when no sibling word in the
 *     same identifier vetoes it, because those words also name ordinary things:
 *     an RNG seed, a GPIO pin, a socket. `--min-confidence medium` filters the
 *     second tier back out and leaves the first-tier vocabulary as it was. That
 *     matters for a gate as well as for a report: `low` is a confidence, not a
 *     severity, so a second-tier finding still carries the rule's `medium` and
 *     `--fail-on medium` alone will fail a build on one. Pair it with
 *     `--min-confidence medium` to gate on the first tier only — measured: the
 *     same input exits 1 with `--fail-on medium` and 0 with both flags. It
 *     does NOT undo the cast form: `memset((void *)password, 0, n)` was always
 *     meant to fire and its absence was a defect, so it reports at the rule's
 *     own confidence like any other first-tier match. On the measured corpus
 *     that is a difference of two findings from the pre-change behaviour, and
 *     both of them are casts over words the vocabulary already contained.
 *   - `memset(secret, '\0', n)` is NOT matched: the character literal is blanked
 *     with strings before the scan. A known, accepted false negative.
 *   - Whether the compiler ACTUALLY removed the store is not decidable here and
 *     is not claimed. The finding is about depending on a removable wipe.
 *   - REGEX_MATCH_LIMIT is first-come, not confidence-ordered, so in a file with
 *     more than 1,000 wipes the second tier can fill the budget ahead of a
 *     first-tier match and that match is not reported. Measured, and left as is:
 *     1,000 first-tier matches already evict the 1,001st today, so this is the
 *     limit's existing behaviour meeting a larger population rather than a new
 *     defect. Ordering the budget by confidence is a change to the limit's
 *     semantics and belongs with the limit, not with this rule.
 *
 * The cast form and the second-tier vocabulary both come from measurement, not
 * from imagination: 720 generated C files were classified, compiled at five
 * optimisation levels on two compilers, and the wipes this rule missed were
 * counted. `compiler/eval/ai-generated/` holds the protocol, the corpus and the
 * numbers.
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
    //
    // THE CAST GROUP. `memset((void *)password, 0, sizeof password)` wipes a
    // secret and the previous pattern did not see it: it admitted `&` but not a
    // cast, so a wipe was silently unreported whenever the model or the author
    // spelled the pointer conversion out. Measured on generated C, the cast form
    // was common enough to matter on its own (see compiler/eval/ai-generated/).
    //
    // It keeps the linearity rule. The group opens with the literal `(`, so the
    // preceding space run is never ambiguous. Inside, the type blob's alphabet
    // EXCLUDES `*`, which makes the blob's end a determined position — the first
    // `*` — rather than something to search for; the trailing `*`s are then a
    // counted run each opening on that literal. Every adjacency in the group is
    // therefore literal-to-run or run-to-disjoint-alphabet, never run-to-run.
    // Non-capturing, so `m[1]` is still the identifier.
    const wipeRe =
      /(?<![\w.>])memset[ \t]{0,8}\([ \t]{0,8}(?:\([ \t]{0,8}[A-Za-z_][A-Za-z0-9_ \t]{0,40}\*[ \t]{0,8}(?:\*[ \t]{0,8}){0,2}\)[ \t]{0,8})?(?:&[ \t]{0,8})?([A-Za-z_][A-Za-z0-9_.>[\]-]{0,60})[ \t]{0,8},[ \t]{0,8}0(?:x0{1,2})?[ \t]{0,8},/g;
    const out: RuleMatch[] = [];
    // Once per scan, not once per match: the second tier is gated on the file.
    //
    // It reads `scanText`, which is already truncated at REGEX_INPUT_CAP, so in a
    // file longer than the cap the context has to appear in the part that is
    // scanned. That is the same text the matching sees, so the two cannot
    // disagree — a match past the cap is not found either.
    const fileHandlesSecrets = SECRET_CONTEXT_RE.test(scanText);
    let m: RegExpExecArray | null;
    while ((m = wipeRe.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      const target = m[1]!;
      const tier = secretTier(target, fileHandlesSecrets);
      if (tier === null) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + m[0].length,
        evidence: `memset(${target}, 0, ...)`,
        // A second-tier name is suggestive, not decisive. Saying so here rather
        // than in the rule's static confidence keeps the first-tier findings at
        // the strength they have always had.
        ...(tier === 'probable' ? { confidence: 'low' as const } : {}),
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

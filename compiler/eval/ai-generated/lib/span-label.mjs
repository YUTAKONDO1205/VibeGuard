/**
 * initialiserLike -- a lexical label per wipe span, reported beside verdicts.
 *
 * wipeSpans finds every zero-fill in the target function body, and a zero-fill
 * is also how a model clears a buffer BEFORE it fills it. The find step labels
 * both "wipe spans", and a verdict about such a span is a verdict about an
 * initialiser (opus_N_pinpad_r2: the only zero-fill is a memset before the
 * keypad is read; sonnet_S_privkey_r3: the only span is a memset before the key
 * file is read). This label says which spans look like that, from the source
 * text alone. It is never folded into a verdict: a span labelled
 * initialiser-like keeps whatever verdict verdictOf gave it, and the label is
 * printed next to it.
 *
 * Definition. For a span inside the target function body:
 *
 *   destination   the object the span zeroes, read as an access path
 *                 `root(.m|->m)*`:
 *                   - a call span (memset, a helper, a volatile function
 *                     pointer): its first argument, after stripping outer
 *                     parentheses, pointer casts such as `(void *)` and a
 *                     leading `&`; subscripts are dropped (`&buf[4]` is `buf`)
 *                     and so is pointer arithmetic (`key + 16` is `key`);
 *                   - a volatile-pointer declaration `volatile T *p = X;`: X;
 *                   - a zeroing loop: the variable its zero store writes
 *                     through, and when that is a pointer declared
 *                     `volatile T *p = X` in the same body, X.
 *                 Anything else (a function call, a dereference `*pp`) has no
 *                 destination, and the label is null.
 *
 *   later         the text that can run after the span, read conservatively
 *                 from the braces:
 *                   - everything from the end of the span onwards, up to the
 *                     first `return` statement that starts at depth 0 of an
 *                     enclosing block (not the body of an if/else/loop without
 *                     braces), searching the innermost block first and then
 *                     each enclosing one; if no such return exists, up to the
 *                     end of the function body;
 *                   - a return is NOT taken as the end when a `goto`, `break`,
 *                     `continue`, `longjmp` or `siglongjmp` appears between the
 *                     span and it -- control might leave by that route instead;
 *                   - plus, for every loop that encloses the span and is not
 *                     left by that return, the loop's text before the span (the
 *                     back edge).
 *
 *   a use         an occurrence of the root as a token in `later`, outside the
 *                 span itself, that is not
 *                   - a member of something else (`x.root`, `x->root`);
 *                   - the operand of `sizeof` (not evaluated);
 *                   - the first argument of a release call (free, OPENSSL_free,
 *                     sodium_free, munlock, munmap, VirtualUnlock, ...): the
 *                     wipe-then-release shape is a wipe;
 *                   - the left side of `root = NULL;` / `root = 0;` (the
 *                     pointer is reset, the buffer is not touched);
 *                   - an operand of an inline assembly statement (`asm`,
 *                     `__asm__`, `__asm`): `__asm__ __volatile__("" : : "r"(buf)
 *                     : "memory")` after a wipe is the compiler-barrier idiom
 *                     that KEEPS the wipe, not a fill or a read the program
 *                     relies on (opus_N_token_r3). The plugin's followedByUse
 *                     does count it -- the asm is an instruction that takes the
 *                     buffer's address -- so this is a designed disagreement;
 *                   - an access through a member path that diverges from the
 *                     destination's (`ctx->keylen` when the span zeroes
 *                     `ctx->key`); the whole object (`ctx`) and a longer path
 *                     (`ctx->key[i]`) do count.
 *
 *   initialiserLike = true when `later` holds a use, false when it holds none,
 *                     null when there is no destination or the target body was
 *                     not found.
 *
 * A later wipe of the same buffer is a write, so the earlier of two wipes of one
 * buffer on the same path reads initialiser-like. That is deliberate: it is also
 * what the repair plugin's followedByUse says ("is this site the buffer's last
 * word?"), and the per-span verdict of the earlier one is then about a store a
 * later store overwrites.
 *
 * What it cannot see, and so where it can be wrong:
 *   - a use through another name: `unsigned char *p = key;` written BEFORE the
 *     span and `p` read after it is not seen (the label errs towards false);
 *   - control flow it does not model: a conditional return is not an end (errs
 *     towards true), a `switch` or `goto` is read as straight-line text, a call
 *     that does not return (`exit`, `abort`) is not an end (errs towards true);
 *   - macros: the text is read as written, not preprocessed, so a use hidden in
 *     a macro expansion is not seen and a macro that happens to be named like the
 *     root is;
 *   - shadowing: a later declaration of another variable with the same name is
 *     read as a use (errs towards true);
 *   - what the use does: reading the zeroed bytes and overwriting them both count.
 *
 * Pure: source text in, labels out. Nothing here compiles or reads a file.
 */
import { maskNonCode, funcBodySpan, stmtEnd, ZERO_WRITE } from './ablation-cell.mjs';

/** Calls whose first argument is released, not read: a wipe before one of these is a wipe. */
export const RELEASE_CALLS = Object.freeze(['free', 'kfree', 'kvfree', 'vfree', 'OPENSSL_free', 'CRYPTO_free',
  'sodium_free', 'g_free', 'munlock', 'munmap', 'VirtualUnlock', 'VirtualFree', 'LocalFree']);

const ESCAPES = /\b(?:goto|break|continue|longjmp|siglongjmp)\b/;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Index of the bracket that closes the one opening at `i` (same kind), or -1. */
function closeOf(s, i) {
  const open = s[i];
  const close = open === '(' ? ')' : open === '[' ? ']' : '}';
  let d = 0;
  for (let k = i; k < s.length; k++) {
    if (s[k] === open) d++;
    else if (s[k] === close) { d--; if (!d) return k; }
  }
  return -1;
}

/**
 * The access path an expression names, or null.
 *
 * `(void *)key` -> key, `&ctx->key[3]` -> ctx->key, `(key)` -> key,
 * `key + 16` -> key, `sizeof x` / `*pp` / `get()` -> null.
 *
 * @returns {{root: string, members: string[]}|null}
 */
export function destinationPath(expr) {
  let s = String(expr).trim();
  for (let guard = 0; guard < 16; guard++) {
    const before = s;
    if (s.startsWith('&')) s = s.slice(1).trim();
    if (s.startsWith('(')) {
      const c = closeOf(s, 0);
      if (c === -1) return null;
      const inner = s.slice(1, c).trim();
      const rest = s.slice(c + 1).trim();
      if (rest === '') s = inner;                                    // (expr)
      else if (/^[A-Za-z_][\w\s]*\*[\s*]*(?:const|volatile|\s)*$/.test(inner)) s = rest; // (T *)expr: a pointer cast
      else if (/^\(|^&|^[A-Za-z_]/.test(rest) && /^(?:const|volatile|unsigned|signed|char|short|int|long|void|struct\s+\w+|u?int\d+_t|size_t|\s)+$/.test(inner)) s = rest; // (T)expr
      else return null;
    }
    if (s === before) break;
  }
  const m = /^([A-Za-z_]\w*)((?:\s*\[[^\]]*\]|\s*(?:\.|->)\s*[A-Za-z_]\w*)*)/.exec(s);
  if (!m) return null;
  if (m[1] === 'sizeof') return null;
  if (/^\s*\(/.test(s.slice(m[0].length))) return null; // get_buf(): a call's result, not a variable
  const members = [...m[2].matchAll(/(?:\.|->)\s*([A-Za-z_]\w*)/g)].map((x) => x[1]);
  return { root: m[1], members };
}

/** The first argument of the call that starts the statement `text`, or null. */
function firstArgument(text) {
  const open = text.indexOf('(');
  if (open === -1) return null;
  let d = 0;
  for (let k = open; k < text.length; k++) {
    const c = text[k];
    if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') { d--; if (d === 0) return text.slice(open + 1, k); }
    else if (c === ',' && d === 1) return text.slice(open + 1, k);
  }
  return null;
}

/** Every `volatile T *p = X;` in [a, b) of the masked text, by name. */
function volatileDecls(masked, a, b) {
  const out = new Map();
  const re = /\bvolatile\b[^;{}]*?\*\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);/g;
  re.lastIndex = a;
  let m;
  while ((m = re.exec(masked)) !== null && m.index < b) out.set(m[1], { at: m.index, init: m[2] });
  return out;
}

/**
 * The destination of one span (masked text of the span, and the body it is in).
 * @returns {{root: string, members: string[]}|null}
 */
export function spanDestination(masked, span, body) {
  const text = masked.slice(span[0], span[1]);
  const decl = /^\s*(?:static\s+)?(?:const\s+)?\bvolatile\b[^;{}]*?\*\s*(?:const\s+)?[A-Za-z_]\w*\s*=\s*([^;]+);\s*$/.exec(text);
  if (decl) return destinationPath(decl[1]);
  if (/^\s*(?:for|while|do)\b/.test(text)) {
    const z = ZERO_WRITE.exec(text);
    if (!z) return null;
    const id = /([A-Za-z_]\w*)/.exec(z[0]);
    if (!id) return null;
    const decls = volatileDecls(masked, body[0], span[0]);
    const d = decls.get(id[1]);
    return d ? destinationPath(d.init) : { root: id[1], members: [] };
  }
  const arg = firstArgument(text);
  return arg === null ? null : destinationPath(arg);
}

/** Enclosing brace blocks of position `p` inside body [a, b), innermost first, as [open, close]. */
function enclosingBlocks(masked, a, b, p) {
  const stack = [];
  for (let k = a; k < p; k++) {
    if (masked[k] === '{') stack.push(k);
    else if (masked[k] === '}') stack.pop();
  }
  return stack.reverse().map((o) => [o, closeOf(masked, o)]).filter(([, c]) => c !== -1 && c < b);
}

/** Loops (for/while/do statements) in body [a, b) that contain the span, as [start, end). */
function enclosingLoops(masked, a, b, span) {
  const out = [];
  const re = /\b(?:for|while|do)\b/g;
  re.lastIndex = a;
  let m;
  while ((m = re.exec(masked)) !== null && m.index < span[0]) {
    const end = stmtEnd(masked, m.index);
    if (end >= span[1] && end <= b) out.push([m.index, end]);
  }
  return out;
}

/**
 * The first `return` statement at depth 0 of block [open, close], at or after
 * `from`, that is a statement of its own (not the braceless body of an if, else
 * or loop). Returns [start, end) of the statement, or null.
 */
function depthZeroReturn(masked, from, close) {
  let d = 0;
  for (let k = from; k < close; k++) {
    const c = masked[k];
    if (c === '{' || c === '(' || c === '[') { d++; continue; }
    if (c === '}' || c === ')' || c === ']') { d--; continue; }
    if (d !== 0 || c !== 'r' || !/^return\b/.test(masked.slice(k, k + 7))) continue;
    if (k > 0 && /\w/.test(masked[k - 1])) continue;
    let j = k - 1;
    while (j >= 0 && /\s/.test(masked[j])) j--;
    if (j >= 0 && !';{}:'.includes(masked[j])) continue; // `if (x) return`, `else return`
    let e = k;
    let dd = 0;
    for (; e < close; e++) {
      if (masked[e] === '(' || masked[e] === '{') dd++;
      else if (masked[e] === ')' || masked[e] === '}') dd--;
      else if (masked[e] === ';' && dd === 0) break;
    }
    return [k, Math.min(e + 1, close)];
  }
  return null;
}

/** The ranges of text that can run after `span`, in body [a, b). See the header. */
export function laterRanges(masked, body, span) {
  const [a, b] = body;
  const blocks = enclosingBlocks(masked, a, b, span[0]);
  let end = b;
  let stopOpen = null;
  let from = span[1];
  for (const [open, close] of blocks) {
    const r = depthZeroReturn(masked, from, close);
    if (r && !ESCAPES.test(masked.slice(span[1], r[0]))) { end = r[1]; stopOpen = open; break; }
    from = close + 1;
  }
  const ranges = [[span[1], end]];
  for (const [ls] of enclosingLoops(masked, a, b, span)) {
    // A loop entirely inside the block whose return ends the path still iterates
    // before reaching that return; a loop around that block does not.
    if (stopOpen === null || ls > stopOpen) ranges.push([ls, span[0]]);
  }
  return ranges;
}

/** Does the occurrence of the root at `k` (in masked text) count as a use of `dest`? */
function isUse(masked, k, dest) {
  const before = masked.slice(Math.max(0, k - 64), k);
  const after = masked.slice(k + dest.root.length, k + dest.root.length + 200);
  if (/(?:\.|->)\s*$/.test(before)) return false;                 // a member of something else
  if (/\bsizeof\s*\(?\s*$/.test(before)) return false;            // not evaluated
  const rel = new RegExp('\\b(?:' + RELEASE_CALLS.map(esc).join('|') + ')\\s*\\(\\s*(?:\\([^()]*\\)\\s*)?$');
  if (rel.test(before) && /^\s*[,)]/.test(after)) return false;   // released, not read
  if (/^\s*=\s*(?:NULL|0|nullptr)\s*;/.test(after)) return false; // the pointer is reset
  if (dest.members.length) {
    const chain = [...(/^((?:\s*\[[^\]]*\]|\s*(?:\.|->)\s*[A-Za-z_]\w*)*)/.exec(after)[1])
      .matchAll(/(?:\.|->)\s*([A-Za-z_]\w*)/g)].map((x) => x[1]);
    const n = Math.min(chain.length, dest.members.length);
    for (let i = 0; i < n; i++) if (chain[i] !== dest.members[i]) return false; // a sibling member
  }
  return true;
}

/** The parenthesised operand lists of every inline asm statement in [a, b), as [open, close]. */
function asmRanges(masked, a, b) {
  const out = [];
  // Every repetition must consume a qualifier word, so a long run of blanks (a
  // masked comment) cannot be split between iterations: no backtracking blow-up.
  const re = /\b(?:__asm__|__asm|asm)\b(?:\s*(?:volatile|__volatile__|goto|inline)\b)*\s*\(/g;
  re.lastIndex = a;
  let m;
  while ((m = re.exec(masked)) !== null && m.index < b) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close !== -1) out.push([open, close]);
  }
  return out;
}

/**
 * initialiserLike for one span.
 * @param {string} masked  maskNonCode(src)
 * @param {[number, number]} body  funcBodySpan(masked, fn)
 * @param {[number, number]} span
 * @returns {boolean|null}
 */
export function initialiserLikeOf(masked, body, span) {
  if (!body || span[0] < body[0] || span[1] > body[1]) return null;
  const dest = spanDestination(masked, span, body);
  if (!dest) return null;
  const re = new RegExp('\\b' + esc(dest.root) + '\\b', 'g');
  const asm = asmRanges(masked, body[0], body[1]);
  for (const [ra, rb] of laterRanges(masked, body, span)) {
    re.lastIndex = ra;
    let m;
    while ((m = re.exec(masked)) !== null && m.index < rb) {
      if (m.index >= span[0] && m.index < span[1]) continue;
      if (asm.some(([o, c]) => m.index > o && m.index < c)) continue; // a barrier operand, not a use
      if (isUse(masked, m.index, dest)) return true;
    }
  }
  return false;
}

/**
 * The label for every span wipeSpans found, in span order.
 * @param {string} src  the source as written
 * @param {string} fn   the target function
 * @param {[number, number][]} spans  wipeSpans(src, fn).spans
 * @returns {(boolean|null)[]}
 */
export function initialiserLabels(src, fn, spans) {
  const masked = maskNonCode(src);
  const body = funcBodySpan(masked, fn);
  return spans.map((sp) => (body ? initialiserLikeOf(masked, body, sp) : null));
}

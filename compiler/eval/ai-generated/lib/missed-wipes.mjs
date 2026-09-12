/**
 * The non-removable wipes `wipeSpans` does not see, by shape. A report beside
 * the find step, never folded into a verdict: the tracked rows keep wipeSpans'
 * labelling (PROTOCOL-r2), and ../README.md reads the idiom table with the files
 * this finds moved, beside the table.
 *
 * wipeSpans pairs a `volatile` pointer with its zeroing loop only where the
 * pointer is declared with an initialiser (`volatile T *p = buf;`), needs the
 * word `volatile` in the loop or in such a declaration, and reads the text as
 * written. Three shapes therefore reach it as nothing at all:
 *
 *   late-pointer    `volatile T *p;` … `p = buf;` … `p[i] = 0;` in a loop --
 *                   the declaration carries no initialiser to pair with.
 *   volatile-array  the buffer itself is `volatile` (`volatile char pin[7];`)
 *                   and a plain loop zeroes it: no `volatile` in the loop.
 *   macro           a function-like macro whose body zeroes through a volatile
 *                   pointer, invoked in the target body: the loop is in the
 *                   macro, and the text is read before preprocessing.
 *
 * A file whose only wipe is one of them is counted as *no wipe*; one that also
 * holds a `memset` is counted as `removable` with that memset as its only span.
 *
 * Lexical, like ./span-label.mjs, and with the same kind of limits: it reads the
 * target function body as text, cannot see a wipe routed through a helper, a
 * macro defined in another file or a store written some other way, and does not
 * check that the object zeroed is the secret. It answers one question only:
 * does this body hold a zeroing loop of one of the three shapes?
 *
 * Pure: source text in, a shape name or null out. Nothing here compiles or
 * reads a file.
 */
import { maskNonCode, funcBodySpan } from './ablation-cell.mjs';

/** The shapes, in the order missedWipeShape reports them. */
export const MISSED_SHAPES = Object.freeze(['late-pointer', 'volatile-array', 'macro']);

/** `<name>[<i>] = 0;` -- the store a zeroing loop makes through `name`. */
const zeroStore = (name) => new RegExp(`\\b${name}\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*(?:0|0x0+|'\\\\0')\\s*;`);

/**
 * `volatile T *p;` with no initialiser, `p` pointed at something later, and a
 * zero store through `p` after that.
 * @param {string} body  the target function body, masked
 */
export function latePointerWipe(body) {
  const decl = /\bvolatile\b[^;{}=()]*\*\s*([A-Za-z_]\w*)\s*;/g;
  let m;
  while ((m = decl.exec(body)) !== null) {
    const p = m[1];
    const after = body.slice(m.index + m[0].length);
    // `p = …;` (an assignment, not a comparison) and then a store through p
    if (new RegExp(`\\b${p}\\s*=\\s*[^=]`).test(after) && zeroStore(p).test(after)) return true;
  }
  return false;
}

/**
 * A buffer declared `volatile` and zeroed element by element afterwards.
 * @param {string} body  the target function body, masked
 */
export function volatileArrayWipe(body) {
  const decl = /\bvolatile\b[^;{}()]*?\b([A-Za-z_]\w*)\s*\[[^\]]*\]\s*(?:=\s*\{[^}]*\})?\s*;/g;
  let m;
  while ((m = decl.exec(body)) !== null) {
    if (zeroStore(m[1]).test(body.slice(m.index + m[0].length))) return true;
  }
  return false;
}

/**
 * A function-like macro whose replacement zeroes through a volatile pointer,
 * invoked in the target body. The definition is read from the source as written
 * (a macro is not code the masker keeps).
 * @param {string} raw   the source as written
 * @param {string} body  the target function body, masked
 */
export function macroWipe(raw, body) {
  const def = /#\s*define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)((?:[^\n]*\\\n)*[^\n]*)/g;
  let m;
  while ((m = def.exec(raw)) !== null) {
    const text = m[3];
    if (/\bvolatile\b/.test(text) && /\[\s*\w+\s*\]\s*=\s*(?:0|0x0+|'\\0')\s*;/.test(text)
      && new RegExp(`\\b${m[1]}\\s*\\(`).test(body)) return true;
  }
  return false;
}

/**
 * The shape of a wipe in `fn`'s body that wipeSpans does not see, or null when
 * there is none (which includes a body wipeSpans does see a wipe in: this asks
 * only about the three shapes).
 * @param {string} src  the source as written
 * @param {string} fn   the target function
 * @returns {'late-pointer'|'volatile-array'|'macro'|null}
 */
export function missedWipeShape(src, fn) {
  const masked = maskNonCode(src);
  const span = funcBodySpan(masked, fn);
  if (!span) return null;
  const body = masked.slice(span[0], span[1]);
  if (latePointerWipe(body)) return 'late-pointer';
  if (volatileArrayWipe(body)) return 'volatile-array';
  if (macroWipe(src, body)) return 'macro';
  return null;
}

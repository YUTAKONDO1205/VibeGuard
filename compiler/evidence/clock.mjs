// The one place in this component that is allowed to read a clock.
//
// THE RULE
//
//   Everything a component writes as evidence must be deterministic: the same
//   measurement, re-run from the same inputs, produces the same bytes.
//   Anything that cannot be made deterministic goes into the record's
//   top-level `context` object, which is removed from the digest as a whole
//   subtree. Nowhere else, and never into a digest.
//
// WHY THIS IS A MODULE AND NOT A CONVENTION
//
//   A pipeline that formats its own timestamps has as many clock call sites as
//   it has writers, and it only takes one of them to break reproducibility for
//   the whole tree. That has already happened once here: a single stage read
//   the wall clock directly while every other stage honoured the pinned epoch,
//   so a re-run under the same `SOURCE_DATE_EPOCH` produced one file that
//   differed and forty that did not — and the one that differed was the one
//   nobody suspected, because "the epoch is set" was true.
//
//   So: `nowIso()` is the only timestamp source, and `auditDirectClockUse()`
//   below is a check that can be run over a directory to prove no second one
//   has appeared. A rule with no check attached is a comment.
//
// SOURCE_DATE_EPOCH
//
//   Whole seconds since the Unix epoch, decimal, no sign — the
//   reproducible-builds spelling. When it is set, every timestamp written here
//   derives from it. A sloppy parse (`Number('12 apples')`) would let a typo
//   become a different timestamp in every file, so the parse is exact and a
//   malformed value throws at import rather than degrading to the wall clock.
//
//   A timestamp somebody supplied is not evidence of when anything happened.
//   Neither was the one it replaced: a local process can write any string it
//   likes into a timestamp field, and it was already doing so from a clock
//   nobody checked. What changed is that the injection is declared —
//   `timeSource` and `sourceDateEpoch` are always recorded, including when no
//   epoch was given, so a reader can tell the two situations apart.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const RAW = process.env.SOURCE_DATE_EPOCH;

function parseEpoch(raw) {
  if (raw === undefined || raw === null || String(raw).trim() === '') return null;
  const s = String(raw).trim();
  if (!/^[0-9]{1,15}$/.test(s)) {
    throw new Error(
      'SOURCE_DATE_EPOCH must be whole seconds since the Unix epoch in decimal, got ' +
        JSON.stringify(raw),
    );
  }
  const n = Number(s);
  if (!Number.isSafeInteger(n)) {
    throw new Error(`SOURCE_DATE_EPOCH ${s} is not representable as an exact integer`);
  }
  return n;
}

/** Whole seconds, or null when the environment did not pin the clock. */
export const SOURCE_DATE_EPOCH = parseEpoch(RAW);

/** `'SOURCE_DATE_EPOCH'` or `'wall-clock'`. Always recorded, never inferred later. */
export const TIME_SOURCE = SOURCE_DATE_EPOCH === null ? 'wall-clock' : 'SOURCE_DATE_EPOCH';

/** Function form of {@link TIME_SOURCE}, for callers that prefer a call. */
export function timeSource() {
  return TIME_SOURCE;
}

/**
 * The timestamp every writer in this component must use.
 *
 * @returns {string} ISO 8601, milliseconds, `Z`.
 */
export function nowIso() {
  const d = SOURCE_DATE_EPOCH === null ? new Date() : new Date(SOURCE_DATE_EPOCH * 1000);
  return d.toISOString();
}

/** Interpreter identity. Pinned by nothing here; recorded so drift is visible. */
export function hostContext() {
  return { node: process.version, platform: process.platform, arch: process.arch };
}

/**
 * The volatile block: the value a record's top-level `context` should hold.
 * Everything in here is excluded from the evidence digest as a subtree, and is
 * still inside the file, so it is still covered by any seal over the bytes.
 *
 * @param {Record<string, unknown>} [extra] Additional volatile fields —
 *   repository provenance, for instance. Merged in after the fixed ones so a
 *   caller cannot silently overwrite `timeSource`.
 */
export function runContext(extra = {}) {
  return {
    ...extra,
    generatedAt: nowIso(),
    timeSource: TIME_SOURCE,
    sourceDateEpoch: SOURCE_DATE_EPOCH,
    host: hostContext(),
  };
}

// ---------------------------------------------------------------------------
// The check that keeps the rule true.
// ---------------------------------------------------------------------------

/** Wall-clock reads that must not appear outside this file. */
const CLOCK_PATTERNS = Object.freeze([
  { kind: 'Date.now', re: /\bDate\s*\.\s*now\s*\(/g },
  { kind: 'new Date()', re: /\bnew\s+Date\s*\(\s*\)/g },
  { kind: 'performance.now', re: /\bperformance\s*\.\s*now\s*\(/g },
  { kind: 'process.hrtime', re: /\bprocess\s*\.\s*hrtime\b/g },
  { kind: 'process.uptime', re: /\bprocess\s*\.\s*uptime\s*\(/g },
]);

/**
 * Replace the contents of comments and of string/template literals with
 * spaces, preserving offsets so line numbers survive.
 *
 * Doing this properly matters: a scanner that greps raw source flags the
 * sentence in this file's own header that names the call it is looking for,
 * and a check that cries wolf on prose gets switched off within a week.
 */
export function blankCommentsAndStrings(src) {
  const out = src.split('');
  const n = src.length;
  let i = 0;
  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  // Tracks whether a `/` starts a regex literal or is a division sign. Good
  // enough for this purpose: we only need the regex body blanked so that a
  // pattern inside it is not mistaken for code.
  let prevSignificant = '';
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === '/' && c2 === '/') {
      let j = i + 2;
      while (j < n && src[j] !== '\n') j++;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '/' && c2 === '*') {
      let j = i + 2;
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      blank(i, Math.min(j + 2, n));
      i = Math.min(j + 2, n);
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') {
          j += 2;
          continue;
        }
        if (src[j] === c) break;
        j++;
      }
      blank(i + 1, j);
      i = Math.min(j + 1, n);
      prevSignificant = c;
      continue;
    }
    if (c === '/' && !/[A-Za-z0-9_)\]]/.test(prevSignificant)) {
      // Regex literal.
      let j = i + 1;
      let inClass = false;
      while (j < n && src[j] !== '\n') {
        if (src[j] === '\\') {
          j += 2;
          continue;
        }
        if (src[j] === '[') inClass = true;
        else if (src[j] === ']') inClass = false;
        else if (src[j] === '/' && !inClass) break;
        j++;
      }
      if (j < n && src[j] === '/') {
        blank(i + 1, j);
        i = j + 1;
        prevSignificant = '/';
        continue;
      }
    }
    if (!/\s/.test(c)) prevSignificant = c;
    i++;
  }
  return out.join('');
}

function listSources(dir) {
  const found = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(mjs|cjs|js)$/.test(e.name)) found.push(p);
    }
  };
  if (statSync(dir).isDirectory()) walk(dir);
  else found.push(dir);
  return found.sort();
}

/**
 * Scan a directory for wall-clock reads outside this module.
 *
 * @param {string} dir
 * @param {{exempt?: string[]}} [opts] Basenames allowed to read a clock;
 *   defaults to this file alone.
 * @returns {{filesScanned: number, sites: Array<{file: string, line: number, kind: string, text: string}>}}
 */
export function auditDirectClockUse(dir, opts = {}) {
  // The exemption is a path, not a basename. Keyed on the basename it applied
  // to any file called clock.mjs anywhere beneath the directory, so dropping one
  // in a subdirectory bought a blanket pass for whatever it contained. There is
  // one file that is allowed to read a clock, and it is this one.
  const exempt = new Set(opts.exempt ?? ['clock.mjs']);
  const files = listSources(dir);
  const sites = [];
  let examined = 0;
  for (const f of files) {
    const rel = relative(dir, f).split(sep).join('/');
    if (exempt.has(rel)) continue;
    examined += 1;
    const src = readFileSync(f, 'utf8');
    const code = blankCommentsAndStrings(src);
    for (const { kind, re } of CLOCK_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(code)) !== null) {
        const line = code.slice(0, m.index).split('\n').length;
        sites.push({
          file: relative(dir, f).split(sep).join('/') || f,
          line,
          kind,
          text: src.split('\n')[line - 1].trim(),
        });
      }
    }
  }
  // `filesScanned` counted the exempt files too, so a directory holding nothing
  // but exemptions reported a non-zero scan. `examined` is what was actually
  // read, and it is what the caller decides on.
  return { filesScanned: files.length, filesExamined: examined, sites };
}

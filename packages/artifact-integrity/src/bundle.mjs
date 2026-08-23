// Observing a JavaScript bundle — the artefact layer for projects that ship a
// build rather than a binary.
//
// ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
//
// Everything else in this package reads ELF. That is the right artefact for a
// compiled program and the wrong one for the projects this scanner was built
// for: a person who writes an application with an assistant ships a bundle, and
// the transformation between what they read and what they ship is a minifier,
// not an optimising back end. The phenomenon is the same one — a defence that
// is in the source and not in the shipped bytes — and it is reachable with far
// less machinery, because a bundle is text and the build hands you a map.
//
// Measured 2026-08-23, esbuild 0.21.5, no flags beyond `--minify` and the
// default browser platform:
//
//     export function deleteUser(session, targetId) {
//       if (process.env.NODE_ENV !== 'production') {
//         if (!session.isAdmin) throw new Error('forbidden');
//       }
//       console.assert(session.isAdmin, 'admin required');
//       if (AUDIT) console.log('AUDIT delete', session.user, targetId);
//       return db.remove(targetId);
//     }
//
// becomes `function o(s,e){return db.remove(e)}`. The parameter carrying the
// caller's identity is never read. Both the source and that output were
// reported clean by the shipped scanner.
//
// ── THE TWO OBSERVATIONS, AND WHY THE SECOND ONE NEEDS NO ORACLE ────────────
//
// 1. WITNESS SURVIVAL. Given a token that a defence is spelled with — a symbol
//    name, a thrown message — does it occur in the shipped bytes? This needs
//    somebody to have said which token matters, i.e. it needs an oracle, and
//    the oracle is the hard part of the whole design.
//
// 2. SIDECAR REPUBLICATION. A source map's `sourcesContent` is the original
//    text, shipped next to the bundle. So a defence the minifier removed from
//    the code that runs is very often still published, in full, in a file
//    served from the same directory. This needs no oracle at all: it is a
//    `must-not-appear` question asked of a file the build wrote, and both
//    halves of the answer come from the build's own output. Measured on the
//    specimen above: `isAdmin`, `forbidden`, `console.assert` and `AUDIT` are
//    all absent from `app.js` and all present in `app.js.map`.
//
// Observation 2 is what makes this module useful before the oracle problem is
// solved, which is why it is the one that runs unconditionally.
//
// ── FAILING IN THE RIGHT DIRECTION ──────────────────────────────────────────
//
// The controlling rule is `packages/evidence-bundle/src/states.mjs`: a
// measurement with a dead control is broken, not clean. Applied here, that
// means this module never reports `ABSENT` — the finding polarity — off an
// input it could not parse or a bundle it could not read. Every path that
// cannot see returns `NOT_OBSERVED`, and the caller is expected to print that
// rather than swallow it. The failure this is guarding against is concrete: a
// source map that fails `JSON.parse` yields zero republished witnesses, and
// zero republished witnesses read as "clean" unless something insists on the
// difference.

import { readFile, readdir, stat } from 'node:fs/promises';
import { extname, join, relative, sep } from 'node:path';

/**
 * The six states, duplicated from `properties.mjs` rather than imported, for
 * one reason: this module must be readable on its own by someone checking that
 * it never produces the finding polarity from a blind path. Re-exported so a
 * caller need not import two modules to compare.
 */
export { STATE } from './properties.mjs';

/** Largest file this module will read into memory. */
export const MAX_ARTEFACT_BYTES = 64 * 1024 * 1024;

/** Extensions that are plausibly shipped executable text. */
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx']);

/**
 * Walk a build output directory and pair each code file with its source map.
 *
 * Pairing is by the two conventions a bundler actually uses: a sibling
 * `<name>.map`, and a `sourceMappingURL` comment. The comment wins when both
 * exist, because it is what a browser follows and therefore what is actually
 * published. A `data:` URL map is read inline; an absolute http(s) URL is NOT
 * fetched — this package makes no network calls — and is recorded as an
 * unreadable map so the pair still reports `NOT_OBSERVED` rather than silently
 * looking clean.
 */
export async function collectArtefacts(dir) {
  const out = [];
  const skipped = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = await readdir(cur, { withFileTypes: true });
    } catch {
      skipped.push({ path: cur, reason: 'directory could not be read' });
      continue;
    }
    for (const e of entries) {
      const full = join(cur, e.name);
      if (e.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!e.isFile()) {
        // A symlink, a Windows junction, a socket. `readdir` with
        // `withFileTypes` does not follow links, so a chunk reached through one
        // — the ordinary shape of a pnpm deploy tree or an Nx output — fell
        // through both branches into nothing: not observed, and not mentioned.
        // Still not followed, for the same reason the source walk does not
        // follow one; what changes is that the omission is recorded, so a claim
        // that reads LOST cannot be resting on a chunk nobody opened.
        if (CODE_EXT.has(extname(e.name).toLowerCase())) {
          skipped.push({ path: full, reason: 'not a regular file (link or special) and not followed' });
        }
        continue;
      }
      if (!CODE_EXT.has(extname(e.name).toLowerCase())) continue;
      let info;
      try {
        info = await stat(full);
      } catch {
        skipped.push({ path: full, reason: 'file could not be stat-ed' });
        continue;
      }
      if (info.size > MAX_ARTEFACT_BYTES) {
        skipped.push({ path: full, reason: `${info.size} bytes exceeds ${MAX_ARTEFACT_BYTES}` });
        continue;
      }
      out.push({ path: full, relPath: relative(dir, full).split(sep).join('/'), bytes: info.size });
    }
  }
  out.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return { artefacts: out, skipped };
}

/** Extract the `sourceMappingURL` a bundle points at, or null. */
export function sourceMappingUrl(code) {
  // Last one wins: concatenated bundles can carry several, and the browser
  // honours the last. Bounded so a pathological file cannot make this quadratic.
  const re = /\/\/[#@]\s*sourceMappingURL=([^\s'"]{1,2048})/g;
  let last = null;
  let m;
  while ((m = re.exec(code)) !== null) last = m[1];
  return last;
}

/**
 * Read the source map belonging to a bundle.
 *
 * Returns `{ map, origin }` on success and `{ map: null, why }` otherwise. The
 * `why` is not decoration: it is what turns a zero-witness result into
 * `NOT_OBSERVED` instead of a clean bill of health.
 */
export async function readSourceMap(artefactPath, code) {
  const url = sourceMappingUrl(code);
  if (url && /^data:/i.test(url)) {
    const comma = url.indexOf(',');
    if (comma < 0) return { map: null, why: 'inline source map has no payload' };
    const payload = url.slice(comma + 1);
    const isB64 = /;base64/i.test(url.slice(0, comma));
    try {
      const text = isB64
        ? Buffer.from(payload, 'base64').toString('utf8')
        : decodeURIComponent(payload);
      return { map: JSON.parse(text), origin: 'inline' };
    } catch (err) {
      return { map: null, why: `inline source map did not parse: ${err.message}` };
    }
  }
  if (url && /^https?:/i.test(url)) {
    return { map: null, why: `source map is at a remote URL (${url}) and this package makes no network calls` };
  }
  const candidates = [];
  if (url) candidates.push(join(artefactPath, '..', url));
  candidates.push(`${artefactPath}.map`);
  for (const c of candidates) {
    let text;
    try {
      text = await readFile(c, 'utf8');
    } catch {
      continue;
    }
    try {
      return { map: JSON.parse(text), origin: c };
    } catch (err) {
      return { map: null, why: `${c} did not parse as JSON: ${err.message}` };
    }
  }
  return { map: null, why: 'no source map was found next to the artefact' };
}

/**
 * Text normalisation for every comparison in this file.
 *
 * A finding's snippet is read off a file on disk and a map's `sourcesContent`
 * is JSON, so on Windows one side routinely has CRLF and the other LF. Without
 * this the identity control below would fail on every claim and the whole
 * feature would report NOT_OBSERVED for everything — true, and silently
 * useless, which is the failure mode that is hardest to notice.
 */
export function normaliseText(s) {
  return String(s).replace(/\r\n/g, '\n');
}

/**
 * A token no source file can contain, used as the NEGATIVE control.
 *
 * The positive control (does this map carry the text we are asking about?) and
 * this one bracket the observer from both sides. If a canary is ever "found",
 * the matcher is matching things that are not there — a substring search over
 * an accidentally-empty haystack, a normalisation that collapsed everything, a
 * regex that became `.*` — and every verdict from that artefact is void.
 *
 * Deterministic, because this file may not call Math.random and a fixed token
 * is equally unfindable.
 */
export const CANARY = 'vibeguard‑canary‑a6f31c0e‑must‑never‑match';

/**
 * Read one artefact and the source map beside it.
 *
 * Returns the artefact's own text and the joined `sourcesContent`, so the
 * adjudicator can ask both "is this artefact the one my claim is about?" and
 * "is my witness in it?" without this module knowing what a claim is.
 *
 * `controlHeld` is the NEGATIVE control only. Whether an artefact is the right
 * one for a given claim is a per-claim question and is answered in
 * `cross-examine.mjs`; a single global positive control could only ever say
 * "some source was mapped", which is what the previous `control: 'function'`
 * said and why a stale map from an earlier build could settle a claim.
 */
export async function observeArtefact(path, relPath, bytes) {
  let code;
  try {
    code = await readFile(path, 'utf8');
  } catch (err) {
    return { artefact: relPath, bytes, code: null, sidecar: null, controlHeld: false,
      why: `artefact could not be read: ${err.message}` };
  }
  const { map, why } = await readSourceMap(path, code);
  if (!map) {
    return { artefact: relPath, bytes, code: normaliseText(code), sidecar: null, controlHeld: false, why };
  }
  const contents = Array.isArray(map.sourcesContent)
    ? map.sourcesContent.filter((x) => typeof x === 'string')
    : [];
  if (!contents.length) {
    return { artefact: relPath, bytes, code: normaliseText(code), sidecar: null, controlHeld: false,
      why: 'the source map carries no sourcesContent, so nothing can be compared against the original text' };
  }
  const sidecar = normaliseText(contents.join('\n'));
  const codeN = normaliseText(code);
  // Negative control. A canary that matches means the matcher is broken.
  if (codeN.includes(CANARY) || sidecar.includes(CANARY)) {
    return { artefact: relPath, bytes, code: null, sidecar: null, controlHeld: false,
      why: 'the negative control matched, so this observer is matching text that is not there and every verdict from this artefact is void' };
  }
  return {
    artefact: relPath,
    bytes,
    code: codeN,
    sidecar,
    sources: Array.isArray(map.sources) ? map.sources.slice(0, 200) : [],
    sourcesContentEntries: contents.length,
    controlHeld: true,
  };
}

/**
 * The whole-directory observation.
 *
 * Deliberately no `witnesses` parameter any more. Deciding which artefact a
 * claim is ABOUT is the step that was missing, it is per claim, and it belongs
 * next to the claim — so this function's job is reduced to producing readable,
 * control-checked text for each artefact, and `crossExamine` does the rest.
 */
export async function observeBundleDir(dir) {
  const { artefacts, skipped } = await collectArtefacts(dir);
  const records = [];
  let held = 0;
  for (const a of artefacts) {
    const r = await observeArtefact(a.path, a.relPath, a.bytes);
    if (r.controlHeld) held += 1;
    records.push(r);
  }
  return { dir, records, skipped, readable: records.length, controlHeld: held };
}

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
      if (!e.isFile()) continue;
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
 * Observation 2 — what the build removed from the code and published anyway.
 *
 * `witnesses` are tokens to look for. For each: present in the shipped code,
 * present in the map's `sourcesContent`, or both. The interesting cell is
 * "absent from the code, present in the map".
 *
 * ── THE CONTROL ─────────────────────────────────────────────────────────────
 *
 * A witness list that finds nothing anywhere is indistinguishable from a
 * `sourcesContent` this function failed to assemble. So the caller must supply
 * `control`: a token that is certainly in the original text. If the control is
 * not found in `sourcesContent`, every verdict in the result is `NOT_OBSERVED`
 * and `controlHeld` is false. This is the rule from `states.mjs` applied
 * locally, and it is the difference between "the map says the defence is gone"
 * and "we never read the map".
 */
export function republishedWitnesses(code, map, witnesses, control) {
  const contents = Array.isArray(map?.sourcesContent)
    ? map.sourcesContent.filter((s) => typeof s === 'string')
    : [];
  const joined = contents.join('\n');
  const controlHeld = control ? joined.includes(control) : contents.length > 0;
  const results = witnesses.map((w) => {
    if (!controlHeld) {
      return { witness: w, state: 'NOT_OBSERVED', inCode: null, inSidecar: null };
    }
    const inCode = code.includes(w);
    const inSidecar = joined.includes(w);
    // The four cells, named rather than inferred by the caller:
    //   in both            PRESENT       — nothing was removed
    //   code only          PRESENT       — shipped, and the map does not carry it
    //   sidecar only       REINTRODUCED  — removed from what runs, published anyway
    //   neither            ABSENT        — not in this artefact at all
    const state = inCode ? 'PRESENT' : inSidecar ? 'REINTRODUCED' : 'ABSENT';
    return { witness: w, state, inCode, inSidecar };
  });
  return {
    controlHeld,
    sourcesContentEntries: contents.length,
    results,
  };
}

/**
 * The whole-directory observation.
 *
 * Returns one record per artefact. `state` at the top of each record is the
 * worst of its witnesses, in the order REINTRODUCED > ABSENT > NOT_OBSERVED >
 * PRESENT — deliberately NOT "any NOT_OBSERVED wins", because an artefact where
 * one witness could not be checked and another was demonstrably republished has
 * something to report, and reporting the unknown would bury it.
 */
export async function observeBundleDir(dir, { witnesses = [], control = null } = {}) {
  const { artefacts, skipped } = await collectArtefacts(dir);
  const records = [];
  for (const a of artefacts) {
    let code;
    try {
      code = await readFile(a.path, 'utf8');
    } catch (err) {
      records.push({
        artefact: a.relPath,
        bytes: a.bytes,
        state: 'NOT_OBSERVED',
        why: `artefact could not be read: ${err.message}`,
        witnesses: [],
        controlHeld: false,
      });
      continue;
    }
    const { map, why } = await readSourceMap(a.path, code);
    if (!map) {
      records.push({
        artefact: a.relPath,
        bytes: a.bytes,
        state: 'NOT_OBSERVED',
        why,
        // Witness survival in the CODE is still answerable without a map, and
        // is reported, but it cannot distinguish "removed" from "renamed", so
        // the record's own state stays NOT_OBSERVED.
        witnesses: witnesses.map((w) => ({
          witness: w,
          state: 'NOT_OBSERVED',
          inCode: code.includes(w),
          inSidecar: null,
        })),
        controlHeld: false,
      });
      continue;
    }
    const r = republishedWitnesses(code, map, witnesses, control);
    records.push({
      artefact: a.relPath,
      bytes: a.bytes,
      state: worstState(r.results.map((x) => x.state)),
      sourcesContentEntries: r.sourcesContentEntries,
      witnesses: r.results,
      controlHeld: r.controlHeld,
      ...(r.controlHeld ? {} : { why: 'the control token was not found in sourcesContent' }),
    });
  }
  return { dir, records, skipped };
}

const STATE_RANK = {
  REINTRODUCED: 4,
  LOST: 3,
  ABSENT: 2,
  NOT_OBSERVED: 1,
  PRESENT: 0,
  NOT_APPLICABLE: 0,
};

export function worstState(states) {
  if (!states.length) return 'NOT_OBSERVED';
  let worst = states[0];
  for (const s of states) if ((STATE_RANK[s] ?? 0) > (STATE_RANK[worst] ?? 0)) worst = s;
  return worst;
}

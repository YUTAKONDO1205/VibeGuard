// The evidence-carrying artefact: an artefact, the record that describes it,
// and a manifest that binds the two together.
//
// ── LAYOUT ──────────────────────────────────────────────────────────────────
//
//   <bundle>/
//     artifact/<name>     the bytes that were produced
//     evidence.json       the sealed evidence-v0 record
//     manifest.json       what is in this bundle, and its digest
//
// ── WHAT BINDS WHAT ─────────────────────────────────────────────────────────
//
//   record.artifact.sha256   binds the RECORD to the ARTEFACT BYTES.
//   manifest.files[]         binds the MANIFEST to every byte of every other
//                            file in the bundle, by digest and by length.
//   manifest.bundleDigest    binds the MANIFEST to itself.
//   manifest.binds.evidenceDigest
//                            binds the MANIFEST to the RECORD.
//
// A one-byte change anywhere in the bundle therefore lands on at least one of
// these, and the verifier says which. That is the whole mechanism, and its
// limit is stated next.
//
// ── THE LIMIT, STATED HERE RATHER THAN BURIED ───────────────────────────────
//
// None of this detects a bundle that was REGENERATED. Every digest above is
// computed from the bundle's own contents, so a bundle rebuilt from different
// inputs is internally consistent and verifies clean — correctly, because the
// verifier's question is "do these files agree with each other?" and the
// answer really is yes.
//
// Detecting that requires binding the bundle to an AUTHORITY the forger does
// not control, which means a signature (and a key, and a way to distribute the
// public half). There is none here. Anyone who can write the bundle directory
// can write a bundle that verifies. That is not a gap to be closed by trying
// harder with hashes; it is what hashes are, and it is written on the tin here,
// in the README, and in the verifier's own output.
//
// ── WHY THE MANIFEST CARRIES `evidenceDigest` TWICE ─────────────────────────
//
// Rule 1 removes the top-level `evidenceDigest` key before digesting. That is
// right for a record — the field cannot commit to itself — but it means a
// top-level `evidenceDigest` on the manifest would sit OUTSIDE `bundleDigest`
// and could be edited without moving it.
//
// The toolchain-side verifier already reads `manifest.evidenceDigest`, so that
// field has to stay where it is. The fix uses the rule rather than fighting it:
// the same value is also carried at `binds.evidenceDigest`, one level down,
// where rule 1 does not reach and `bundleDigest` therefore covers it. The
// verifier checks the two against each other, so editing the outer one is a
// finding rather than a silent success.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';

import {
  CanonError,
  canonicalText,
  canonicalTextRaw,
  digestExcludingSelf,
  evidenceDigest,
  sha256Hex,
} from './canon.mjs';
import { assertNoAbsolutePaths } from './paths.mjs';
import { assertStatesAreSane } from './states.mjs';

export const BUNDLE_SCHEMA_VERSION = 'evidence-bundle-v0';
export const RECORD_SCHEMA_VERSION = 'evidence-v0';
export const EVIDENCE_FILE = 'evidence.json';
export const MANIFEST_FILE = 'manifest.json';
export const ARTIFACT_DIR = 'artifact';

/** The key `bundleDigest` commits to everything except itself. */
export const BUNDLE_SELF_DIGEST_KEY = 'bundleDigest';

export class BundleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BundleError';
  }
}

/**
 * A context block. Everything a re-run cannot reproduce goes here and nothing
 * else, because rule 1 excludes it from every digest.
 *
 * `SOURCE_DATE_EPOCH` is honoured when it is set, which is what makes a bundle
 * built twice from the same inputs produce the same files as well as the same
 * digests.
 *
 * @param {Record<string, unknown>} [extra]
 * @returns {Record<string, unknown>}
 */
export function runContext(extra = {}) {
  const pinned = process.env.SOURCE_DATE_EPOCH;
  const epoch = pinned === undefined ? null : Number.parseInt(pinned, 10);
  const usePin = epoch !== null && Number.isSafeInteger(epoch);
  const millis = usePin ? epoch * 1000 : Date.now();
  return {
    generatedAt: new Date(millis).toISOString(),
    timeSource: usePin ? 'SOURCE_DATE_EPOCH' : 'wall-clock',
    sourceDateEpoch: usePin ? epoch : null,
    host: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    ...extra,
  };
}

/**
 * Seal a record: attach `context`, refuse absolute paths and insane state
 * histories, then set `evidenceDigest`.
 *
 * The order matters. The path gate and the state gate both run BEFORE the
 * digest, so a record that should not exist is never digested and never
 * referenced by a manifest.
 *
 * @param {Record<string, unknown>} record
 * @param {{context?: Record<string, unknown>, contextExtra?: Record<string, unknown>}} [opts]
 * @returns {Record<string, unknown>} a new record; the input is not mutated.
 */
export function sealRecord(record, opts = {}) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new BundleError('a record must be a JSON object');
  }
  const context = opts.context ?? record.context ?? runContext(opts.contextExtra ?? {});
  const sealed = { ...record, context };
  delete sealed.evidenceDigest;

  assertNoAbsolutePaths(sealed, { label: 'record' });
  assertStatesAreSane(sealed);

  const digest = evidenceDigest(sealed);

  // Key order on disk is the authored order; only the canonical text is sorted.
  const out = {};
  for (const k of Object.keys(record)) {
    if (k === 'evidenceDigest') out.evidenceDigest = digest;
    else if (k === 'context') out.context = context;
    else out[k] = record[k];
  }
  if (!('context' in out)) out.context = context;
  if (!('evidenceDigest' in out)) out.evidenceDigest = digest;
  return out;
}

/** Repo-style POSIX relative path, so a manifest reads the same on both platforms. */
function posixRelative(root, abs) {
  return relative(root, abs).split(sep).join('/');
}

/**
 * Every regular file under `dir`, as POSIX-relative paths, sorted.
 *
 * @param {string} dir
 * @param {{exclude?: string[]}} [opts]
 * @returns {string[]}
 */
export function listBundleFiles(dir, opts = {}) {
  const exclude = new Set(opts.exclude ?? []);
  const out = [];
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const abs = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      const rel = posixRelative(dir, abs);
      if (exclude.has(rel)) continue;
      out.push(rel);
    }
  }
  return out.sort();
}

/**
 * The `files[]` block: one entry per file, digest and length.
 *
 * The LENGTH is not redundant with the digest. It is there so that a truncated
 * file is reported as truncated rather than as "content differs" — the two have
 * different causes (a copy that stopped early versus an edit) and telling them
 * apart is most of the value of a report.
 *
 * @param {string} dir
 * @param {string[]} relPaths
 * @returns {Array<{bytes: number, path: string, sha256: string}>}
 */
export function fileEntries(dir, relPaths) {
  return relPaths.map((rel) => {
    const buf = readFileSync(join(dir, rel));
    return { bytes: buf.length, path: rel, sha256: sha256Hex(buf) };
  });
}

/**
 * SHA-256 of the canonical text of a manifest's `context` subtree.
 *
 * Note `canonicalTextRaw`, not `canonicalText`: this is a SUB-object, so rule
 * 1's top-level exclusions must not be applied to it. A `context` key inside
 * `context` is an ordinary key, and the vectors say so.
 *
 * @param {unknown} context
 * @returns {string}
 */
export function contextDigestOf(context) {
  try {
    return sha256Hex(Buffer.from(canonicalTextRaw(context ?? null), 'utf8'));
  } catch (e) {
    if (e instanceof CanonError) {
      throw new BundleError(
        `a manifest's context must be canonicalisable so that contextDigest can commit to it, ` +
          `and this one is not: ${e.message}. A record's context may hold a float because rule 1 ` +
          'drops it before digesting; a manifest\'s may not, because here it is digested on ' +
          'purpose. Carry the value as a pair of integer counts, or leave it out.',
      );
    }
    throw e;
  }
}

/**
 * Build the manifest object for a bundle directory that already holds its
 * files. Returns a NEW object with `bundleDigest` filled in.
 *
 * @param {string} dir
 * @param {{
 *   evidenceDigest: string,
 *   artifact: {path: string, sha256: string}|null,
 *   context: Record<string, unknown>,
 * }} args
 * @returns {Record<string, unknown>}
 */
export function buildManifest(dir, { evidenceDigest: recordDigest, artifact, context }) {
  const files = fileEntries(dir, listBundleFiles(dir, { exclude: [MANIFEST_FILE] }));
  const draft = {
    schemaVersion: BUNDLE_SCHEMA_VERSION,
    bundleDigest: null,
    // Compatibility copy: the toolchain-side verifier reads this name. Rule 1
    // keeps it OUT of the digest, which is why `binds.evidenceDigest` exists.
    evidenceDigest: recordDigest,
    // ── The hole rule 1 opens, and how it is closed ──────────────────────
    //
    // Rule 1 removes the top-level `context` subtree before digesting, so
    // `bundleDigest` says NOTHING about it: `generatedAt`, the host block and
    // the provenance could all be edited afterwards and every digest in the
    // bundle would still check out.
    //
    // `contextDigest` is a top-level field that IS digested, holding the
    // SHA-256 of the canonical text of the `context` subtree. The excluded
    // subtree is thereby committed to by an included field, rule 1 is
    // untouched, and a later edit to `context` is a finding.
    //
    // The price is that a manifest's `context` must itself be canonicalisable
    // — integers only, no `Date`, no floats. That is stricter than a record's
    // `context`, where rule 1 makes a float harmless. It is enforced below
    // rather than discovered later.
    contextDigest: contextDigestOf(context),
    binds: {
      evidenceDigest: recordDigest,
      artifact,
    },
    files,
    context,
  };
  assertNoAbsolutePaths({ ...draft, context: undefined, bundleDigest: undefined }, {
    label: 'manifest',
  });
  return { ...draft, bundleDigest: digestExcludingSelf(draft, BUNDLE_SELF_DIGEST_KEY) };
}

function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

/**
 * Write a whole bundle.
 *
 * @param {string} dir  the bundle directory; created if missing.
 * @param {{
 *   record: Record<string, unknown>,
 *   artifact?: {name: string, bytes: Buffer|Uint8Array, kind?: string}|null,
 *   extraFiles?: Array<{path: string, bytes: Buffer|Uint8Array}>,
 *   context?: Record<string, unknown>,
 * }} args
 * @returns {{dir: string, record: object, manifest: object, evidenceDigest: string, bundleDigest: string}}
 */
export function writeBundle(dir, { record, artifact = null, extraFiles = [], context }) {
  mkdirSync(dir, { recursive: true });

  const ctx = context ?? record?.context ?? runContext();
  let recordToSeal = record;

  if (artifact) {
    const artifactRel = `${ARTIFACT_DIR}/${artifact.name}`;
    if (artifact.name.includes('/') || artifact.name.includes('\\')) {
      throw new BundleError(
        `artefact name ${JSON.stringify(artifact.name)} contains a path separator; the bundle ` +
          `layout puts artefacts directly under ${ARTIFACT_DIR}/`,
      );
    }
    const bytes = Buffer.from(artifact.bytes);
    mkdirSync(join(dir, ARTIFACT_DIR), { recursive: true });
    writeFileSync(join(dir, artifactRel), bytes);
    recordToSeal = {
      ...record,
      artifact: {
        path: artifactRel,
        sha256: sha256Hex(bytes),
        kind: artifact.kind ?? record?.artifact?.kind ?? 'object',
      },
    };
  }

  for (const extra of extraFiles) {
    const abs = join(dir, extra.path);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, Buffer.from(extra.bytes));
  }

  const sealed = sealRecord(recordToSeal, { context: ctx });
  writeJson(join(dir, EVIDENCE_FILE), sealed);

  const manifest = buildManifest(dir, {
    evidenceDigest: sealed.evidenceDigest,
    artifact: sealed.artifact
      ? { path: sealed.artifact.path, sha256: sealed.artifact.sha256 }
      : null,
    context: ctx,
  });
  writeJson(join(dir, MANIFEST_FILE), manifest);

  return {
    dir,
    record: sealed,
    manifest,
    evidenceDigest: sealed.evidenceDigest,
    bundleDigest: manifest.bundleDigest,
  };
}

/** SHA-256 of a file's bytes. Exported so a caller need not import node:crypto. */
export function fileDigest(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

/** True when the path exists and is a directory. */
export function isDirectory(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** The canonical text a record's digest is taken over. Re-exported for callers. */
export { canonicalText };

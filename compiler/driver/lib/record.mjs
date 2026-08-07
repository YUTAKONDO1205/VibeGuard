// The evidence record.
//
// interfaces.md §5. Canonicalisation and digesting come from compiler/evidence/;
// what happens here is assembling a value that is legal to hand to it, and
// refusing to hand over one that is not.
//
// Two guards run before the digest, and they run over the finished value rather
// than at each place a field is set:
//
//   - no absolute path anywhere, because a record that names /mnt/c/... is a
//     record about one machine and the claims made from it do not transfer;
//   - every number an integer, because the canonicaliser is specified to fail
//     rather than round, and a driver that lets the canonicaliser be the one to
//     notice reports the problem as "evidence module error" instead of naming
//     the field.
//
// Either guard tripping is exit 3 with no file written. "We could not describe
// what we did" is not a clean build.

import { mkdirSync, writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { join } from 'node:path';

import { loadEvidenceModule } from './evidence-binding.mjs';
import { findAbsolutePaths, findNonIntegerNumbers } from './paths.mjs';

export const RECORD_VERSION = 'compiler-evidence-v0';

/**
 * Everything a re-run cannot reproduce, and nothing else (interfaces.md §5).
 * Recorded, never digested.
 */
export function buildContext({ sourceDateEpoch }) {
  const usingEpoch = Number.isInteger(sourceDateEpoch.value);
  const when = usingEpoch ? new Date(sourceDateEpoch.value * 1000) : new Date();
  return {
    generatedAt: when.toISOString(),
    timeSource: usingEpoch ? 'SOURCE_DATE_EPOCH' : 'wall-clock',
    sourceDateEpoch: usingEpoch ? sourceDateEpoch.value : null,
    sourceDateEpochFrom: sourceDateEpoch.source,
    host: {
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      cpus: cpus().length,
    },
  };
}

/**
 * Assemble the record. `evidenceDigest` is added by `writeRecord`; it is one of
 * the two subtrees removed before digesting, so its absence here is not a hole.
 */
export function buildRecord(parts) {
  const {
    driverName, mode, policy, invocation, toolchain, checks, build, findings, exitCode, exitReason, context,
  } = parts;
  return {
    build,
    checks,
    component: 'driver',
    context,
    driver: driverName,
    exitCode,
    // Which rule decided the exit code. Without it, a 3 in a bundle of records
    // is a number that has to be reverse-engineered from the other fields.
    exitReason,
    findings,
    invocation,
    mode,
    policy,
    recordVersion: RECORD_VERSION,
    toolchain,
  };
}

/**
 * @returns {Promise<{ok: true, path: string, relPath: string, digest: string, bytes: number}
 *                 | {ok: false, reason: string, detail: string, offenders?: object[]}>}
 */
export async function writeRecord({ record, outDir }) {
  const absolutes = findAbsolutePaths(record);
  if (absolutes.length > 0) {
    return {
      ok: false,
      reason: 'absolute-path',
      detail: absolutes.map((a) => `${a.pointer} = ${JSON.stringify(a.value)}`).join('\n'),
      offenders: absolutes,
    };
  }

  const floats = findNonIntegerNumbers(record);
  if (floats.length > 0) {
    return {
      ok: false,
      reason: 'non-integer-number',
      detail: floats.map((f) => `${f.pointer} = ${f.value}`).join('\n'),
      offenders: floats,
    };
  }

  let evidence;
  try {
    evidence = await loadEvidenceModule();
  } catch (err) {
    return { ok: false, reason: 'evidence-module', detail: err.message };
  }

  // What gets digested and what gets stored are two different strings, and
  // confusing them is easy to do and hard to see. `canonicalJson` removes
  // `context` and `evidenceDigest` — that is its job, it is the digest input —
  // so writing its output to disk would produce a file with no timestamp and no
  // digest in it, which the independent verifier would reject as malformed. The
  // file is the sealed record, pretty-printed; the canonical text exists only
  // long enough to be hashed.
  let sealed;
  let digest;
  try {
    if (evidence.sealRecord) {
      sealed = evidence.sealRecord(record, { context: record.context, pathMode: 'strict', label: 'driver record' });
      digest = sealed.evidenceDigest;
    } else {
      digest = evidence.evidenceDigest(record);
      sealed = { ...record, evidenceDigest: digest };
    }
  } catch (err) {
    return { ok: false, reason: 'canonicalise-failed', detail: err.message };
  }
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    return { ok: false, reason: 'bad-digest', detail: `evidenceDigest returned ${JSON.stringify(digest)}; expected 64 lowercase hex` };
  }
  // The digest must be over the canonical text of what was written, not over
  // some other value that happened to be in scope. Recompute and compare.
  const recomputed = evidence.evidenceDigest(sealed);
  if (recomputed !== digest) {
    return {
      ok: false,
      reason: 'digest-mismatch',
      detail: `the sealed record digests to ${recomputed} but carries ${digest}`,
    };
  }
  const serialised = `${JSON.stringify(sealed, null, 2)}\n`;

  const dir = join(outDir, 'driver');
  mkdirSync(dir, { recursive: true });
  // Content-addressed: the same build writes the same filename, and two
  // different builds cannot land on one file and lose a record.
  const name = `driver-${digest.slice(0, 16)}.json`;
  const path = join(dir, name);
  writeFileSync(path, serialised, 'utf8');
  return { ok: true, path, relPath: join('driver', name), digest, bytes: Buffer.byteLength(serialised, 'utf8') };
}

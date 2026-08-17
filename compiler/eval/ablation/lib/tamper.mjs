// The tamper matrix for component F.
//
// §24 asks "which alterations did the external Verifier detect". A recall number
// over compiled fixtures cannot answer that, because the verifier never looks at
// a compilation — so the question is asked the way it is actually answerable: an
// evidence bundle is copied, one named alteration is applied to the copy, and
// the verifier is run against it.
//
// The first row is the negative control and it is not optional. A verifier that
// reports a finding on every input detects every alteration trivially, so the
// untouched copy must come back VERIFIED_CLEAN or the whole matrix is void and
// is reported as void rather than as eleven detections.
//
// Nothing here writes inside the original bundle. Every mutation is applied to a
// copy under the run's own output directory.

import { cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function updateManifestEntry(bundle, relpath) {
  const mp = path.join(bundle, 'manifest.json');
  const m = JSON.parse(readFileSync(mp, 'utf8'));
  const target = path.join(bundle, relpath);
  const entry = (m.files || []).find((f) => f.relpath === relpath);
  if (entry) {
    const bytes = readFileSync(target);
    entry.sha256 = sha256(bytes);
    entry.size = bytes.length;
  }
  writeFileSync(mp, JSON.stringify(m, null, 2) + '\n');
}

/**
 * Each mutation gets a `class` — what kind of alteration this is — so that the
 * result table groups by the thing being asked about rather than by the eleven
 * individual edits.
 */
export const MUTATIONS = [
  {
    id: 'none',
    class: 'negative-control',
    what: 'nothing is changed',
    expectClean: true,
    apply: () => {},
  },
  {
    id: 'artifact-byte-flipped',
    class: 'artefact-content',
    what: 'one byte of the shipped binary is flipped and no digest is updated',
    apply: (b) => {
      const p = path.join(b, 'artifact', 'a.out');
      const buf = readFileSync(p);
      buf[Math.floor(buf.length / 2)] ^= 0xff;
      writeFileSync(p, buf);
    },
  },
  {
    id: 'artifact-byte-flipped-manifest-updated',
    class: 'artefact-content-with-recomputed-digest',
    what: 'the binary is altered and the manifest digest is recomputed over the altered bytes',
    apply: (b) => {
      const p = path.join(b, 'artifact', 'a.out');
      const buf = readFileSync(p);
      buf[Math.floor(buf.length / 2)] ^= 0xff;
      writeFileSync(p, buf);
      updateManifestEntry(b, 'artifact/a.out');
    },
  },
  {
    id: 'evidence-field-edited',
    class: 'record-content',
    what: 'a value inside evidence.json is rewritten and no digest is updated',
    apply: (b) => {
      const p = path.join(b, 'evidence.json');
      const t = readFileSync(p, 'utf8');
      writeFileSync(p, t.replace('"clang-18"', '"clang-99"'));
    },
  },
  {
    id: 'evidence-field-edited-manifest-updated',
    class: 'record-content-with-recomputed-digest',
    what: 'evidence.json is rewritten and the manifest digest is recomputed over the rewrite',
    apply: (b) => {
      const p = path.join(b, 'evidence.json');
      const t = readFileSync(p, 'utf8');
      writeFileSync(p, t.replace('"clang-18"', '"clang-99"'));
      updateManifestEntry(b, 'evidence.json');
    },
  },
  {
    id: 'file-added',
    class: 'bundle-membership',
    what: 'a file the manifest does not list is added to the bundle',
    apply: (b) => writeFileSync(path.join(b, 'extra.txt'), 'not in the manifest\n'),
  },
  {
    id: 'file-removed',
    class: 'bundle-membership',
    what: 'a file the manifest lists is deleted',
    apply: (b) => rmSync(path.join(b, 'artifact', 'a.out')),
  },
  {
    id: 'signature-removed',
    class: 'seal-presence',
    what: 'the detached signature is deleted',
    apply: (b) => rmSync(path.join(b, 'manifest.sig')),
  },
  {
    id: 'signature-from-another-bundle',
    class: 'seal-substitution',
    what: 'the signature of a different, genuinely signed bundle is put in place of this one',
    needsDonor: true,
    apply: (b, { donor }) => cpSync(path.join(donor, 'manifest.sig'), path.join(b, 'manifest.sig')),
  },
  {
    id: 'symlink-escape',
    class: 'path-escape',
    what: 'a bundle member is replaced by a symlink to a file outside the bundle',
    apply: (b) => {
      const p = path.join(b, 'evidence.json');
      rmSync(p);
      symlinkSync('/etc/hostname', p);
    },
  },
  {
    id: 'manifest-duplicate-key',
    class: 'record-parse-ambiguity',
    what: 'the manifest gains a second "bundleId" key with a different value',
    apply: (b) => {
      const p = path.join(b, 'manifest.json');
      const t = readFileSync(p, 'utf8');
      writeFileSync(p, t.replace(/\{\n/, '{\n  "bundleId": "something-else",\n'));
    },
  },
];

/**
 * Run the whole matrix.
 *
 * @param run     the pinned-environment runner
 * @param verifier  path to evidence-verify.mjs
 * @param bundle    the bundle to copy (never written to)
 * @param donor     a second signed bundle, for the substitution row
 * @param pubkey    a public key from OUTSIDE the bundle
 * @param workDir   where the copies go
 */
export function runTamperMatrix({ run, verifier, bundle, donor, pubkey, workDir }) {
  const rows = [];
  if (!existsSync(verifier)) {
    return { status: 'UNSUPPORTED', reason: `no verifier at ${verifier}`, rows };
  }
  if (!existsSync(bundle)) {
    return { status: 'UNSUPPORTED', reason: `no bundle at ${bundle}`, rows };
  }
  if (!existsSync(pubkey)) {
    return {
      status: 'UNSUPPORTED',
      reason:
        `no public key at ${pubkey}. The verifier refuses a key found inside the bundle, so without an ` +
        'external key every row would come back UNSIGNED and the matrix would measure nothing',
      rows,
    };
  }

  for (const m of MUTATIONS) {
    if (m.needsDonor && (!donor || !existsSync(donor))) {
      rows.push({ id: m.id, class: m.class, what: m.what, status: 'UNSUPPORTED', reason: 'no second signed bundle available to take a signature from' });
      continue;
    }
    const dst = path.join(workDir, m.id, path.basename(bundle));
    rmSync(path.join(workDir, m.id), { recursive: true, force: true });
    mkdirSync(path.dirname(dst), { recursive: true });
    cpSync(bundle, dst, { recursive: true });
    try {
      m.apply(dst, { donor });
    } catch (e) {
      rows.push({ id: m.id, class: m.class, what: m.what, status: 'UNSUPPORTED', reason: `the mutation could not be applied: ${e.message}` });
      continue;
    }
    const r = run('node', [verifier, dst, '--pubkey', pubkey, '--json']);
    let parsed = null;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      parsed = null;
    }
    const verdict = parsed ? parsed.verdict : null;
    rows.push({
      id: m.id,
      class: m.class,
      what: m.what,
      exitCode: r.status,
      verdict,
      findingCodes: parsed && parsed.findings ? parsed.findings.map((f) => f.code || f.id || String(f)).slice(0, 8) : [],
      // "Detected" means the verifier refused to call the bundle clean. It does
      // NOT mean the verifier named the alteration correctly; the verdict string
      // is recorded next to it so a reader can see which of the two happened.
      detected: verdict != null && verdict !== 'VERIFIED_CLEAN',
      status: parsed ? 'RAN' : 'VERIFICATION_INCOMPLETE',
      reason: parsed ? null : `the verifier produced no parseable JSON (exit ${r.status}): ${r.stderr.slice(0, 200)}`,
    });
  }

  const control = rows.find((r) => r.id === 'none');
  const controlHeld = Boolean(control && control.verdict === 'VERIFIED_CLEAN');
  const measured = rows.filter((r) => r.id !== 'none' && r.status === 'RAN');
  return {
    status: controlHeld ? 'RAN' : 'VOID',
    reason: controlHeld
      ? null
      : `the untouched copy came back ${control ? control.verdict : 'unparseable'} instead of VERIFIED_CLEAN. ` +
        'A verifier that rejects an unaltered bundle detects every alteration trivially, so no detection ' +
        'in this matrix is evidence of anything',
    negativeControl: control || null,
    detected: controlHeld ? measured.filter((r) => r.detected).length : null,
    ofMutations: controlHeld ? measured.length : null,
    classesDetected: controlHeld ? [...new Set(measured.filter((r) => r.detected).map((r) => r.class))].sort() : [],
    classesMissed: controlHeld ? [...new Set(measured.filter((r) => !r.detected).map((r) => r.class))].sort() : [],
    rows,
  };
}

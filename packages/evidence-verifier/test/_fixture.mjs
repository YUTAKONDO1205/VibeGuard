// Fixtures for the verifier's tests.
//
// ── THE ONE PLACE THIS PACKAGE TOUCHES THE OTHER ONE ────────────────────────
//
// The import below is a relative path into the generator package, and it is
// deliberate and confined to test fixtures:
//
//   * a rejection test needs a bundle that was built CORRECTLY, or it is
//     testing its own fixture-writing code rather than the verifier;
//   * it is a relative file path rather than a package specifier because the
//     two packages declare no dependency on each other. A dependency edge
//     between them would be a lie about the runtime relationship — the verifier
//     genuinely does not need the generator to verify anything — and it would
//     be the first step towards someone importing the generator's canonicaliser
//     into `rederive.mjs`, which is the one thing that would make this whole
//     package meaningless;
//   * nothing under `src/` or `bin/` imports it, so the shipped surface of this
//     package remains self-contained.
//
// If the packages are ever separated, this file is the thing that has to move.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeBundle } from '../../evidence-bundle/src/bundle.mjs';

/** Fixed, so a bundle built twice from the same inputs is byte-identical. */
export const FIXED_CONTEXT = Object.freeze({
  generatedAt: '2020-01-01T00:00:00.000Z',
  timeSource: 'SOURCE_DATE_EPOCH',
  sourceDateEpoch: 1577836800,
  host: { node: 'v20.0.0', platform: 'linux', arch: 'x64' },
});

/** Short on purpose: a full byte-by-byte sweep runs over these bytes. */
export const ARTIFACT_BYTES = Buffer.from('64-bytes-of-fixture-standing-in-for-an-object-file', 'latin1');

/**
 * A complete, internally consistent evidence-v0 record. Complete matters: the
 * negative direction of every rejection test is "the untouched bundle verifies
 * CLEAN", and a record with a hole in it verifies INCOMPLETE instead, which
 * would let a rejection test pass without the rejection working.
 */
export function demoRecord(overrides = {}) {
  return {
    schemaVersion: 'evidence-v0',
    context: FIXED_CONTEXT,
    evidenceDigest: 'to-be-replaced',
    toolchain: {
      digest: '0'.repeat(64),
      clang: '18.1.3',
      packages: [{ name: 'llvm-18-dev', version: '18.1.3' }],
    },
    command: { argv: ['cc', '-O2', '-c', '-o', 'build/wipe.o', 'src/wipe.c'] },
    artifact: { path: 'artifact/wipe.o', sha256: '0'.repeat(64), kind: 'object' },
    coverage: { observed: 2, planned: 2 },
    properties: [
      {
        propertyId: 'demo.erasure',
        states: [
          // Call sites of the zeroing instruction, never a symbol-name match.
          { checkpoint: 'ir-pre', verdict: 'PRESENT', state: 'PRESENT', effect: 1, control: 1 },
          // The subject goes to zero; the CONTROL keeps its store, which is the
          // only thing that distinguishes an optimisation from a broken harness.
          { checkpoint: 'ir-post', verdict: 'ABSENT', state: 'LOST', effect: 0, control: 1 },
        ],
        firstLoss: { stage: 'ir-pass', pass: 'DemoPass', unit: 'wipe', occurrence: 1 },
        agreement: { level: 'single', methods: ['ir'], reportedUnits: { ir: 'wipe' } },
        confidence: 'provisional',
        fragility: { lost: 1, evaluated: 4 },
      },
    ],
    unresolved: [],
    ...overrides,
  };
}

export function scratchDir(prefix = 'eca-v-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return {
    dir,
    dispose() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * A correctly built bundle in a fresh scratch directory.
 *
 * @param {{record?: object, artifact?: object|null, prefix?: string, context?: object}} [opts]
 */
export function buildFixtureBundle(opts = {}) {
  const scratch = scratchDir(opts.prefix);
  const bundleDir = join(scratch.dir, 'bundle');
  const result = writeBundle(bundleDir, {
    record: opts.record ?? demoRecord(),
    artifact:
      opts.artifact === undefined
        ? { name: 'wipe.o', bytes: ARTIFACT_BYTES, kind: 'object' }
        : opts.artifact,
    context: opts.context ?? FIXED_CONTEXT,
  });
  return { ...result, scratch, bundleDir };
}

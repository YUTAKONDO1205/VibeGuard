// Shared fixtures. Not a test file: the name does not end in `.test.mjs`, so
// the runner does not pick it up.
//
// The record below is deliberately COMPLETE — every field the verifier looks at
// is present and consistent — because the negative direction of the whole test
// suite is "an untouched bundle verifies clean", and a fixture with a hole in
// it verifies as INCOMPLETE instead, which would make every rejection test pass
// for the wrong reason.
//
// The measurement it describes is the shape the oracle rule requires: counts of
// the zeroing CALL SITE, a control whose effect cannot be optimised away, and a
// subject that goes nonzero to zero while the control stays nonzero.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeBundle } from '../src/bundle.mjs';

/** Fixed, so a bundle built twice from the same inputs is byte-identical. */
export const FIXED_CONTEXT = Object.freeze({
  generatedAt: '2020-01-01T00:00:00.000Z',
  timeSource: 'SOURCE_DATE_EPOCH',
  sourceDateEpoch: 1577836800,
  host: { node: 'v20.0.0', platform: 'linux', arch: 'x64' },
});

/** The artefact bytes. Short, so a full byte-by-byte sweep is cheap. */
export const ARTIFACT_BYTES = Buffer.from(
  'ELF-not-really-an-object-file-just-64-bytes-of-fixture-content!',
  'latin1',
);

/**
 * A complete, internally consistent evidence-v0 record.
 *
 * @param {Record<string, unknown>} [overrides]
 * @returns {Record<string, unknown>}
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
    command: {
      argv: ['cc', '-O2', '-c', '-o', 'build/wipe.o', 'src/wipe.c'],
    },
    artifact: {
      path: 'artifact/wipe.o',
      sha256: '0'.repeat(64),
      kind: 'object',
    },
    coverage: { observed: 2, planned: 2 },
    properties: [
      {
        propertyId: 'demo.erasure',
        states: [
          {
            checkpoint: 'ir-pre',
            verdict: 'PRESENT',
            state: 'PRESENT',
            // Call sites of the zeroing instruction, never a symbol-name match:
            // a deleted call leaves its `declare` behind, and counting the name
            // attributes the loss to whichever pass later sweeps declarations.
            effect: 1,
            control: 1,
          },
          {
            checkpoint: 'ir-post',
            verdict: 'ABSENT',
            state: 'LOST',
            effect: 0,
            // The control keeps its store. A run where this also fell to zero
            // is a broken measurement, not a finding.
            control: 1,
          },
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

/** A scratch directory that cleans itself up. */
export function scratchDir(prefix = 'eca-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return {
    dir,
    dispose() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Build a complete bundle in a fresh scratch directory.
 *
 * @param {{record?: object, artifact?: object|null, prefix?: string}} [opts]
 */
export function buildFixtureBundle(opts = {}) {
  const scratch = scratchDir(opts.prefix ?? 'eca-bundle-');
  const bundleDir = join(scratch.dir, 'bundle');
  const result = writeBundle(bundleDir, {
    record: opts.record ?? demoRecord(),
    artifact:
      opts.artifact === undefined
        ? { name: 'wipe.o', bytes: ARTIFACT_BYTES, kind: 'object' }
        : opts.artifact,
    context: FIXED_CONTEXT,
  });
  return { ...result, scratch, bundleDir };
}

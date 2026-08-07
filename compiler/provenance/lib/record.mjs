// The provenance record: the SLSA statement wrapped in something the evidence
// rules can seal.
//
// WHY A WRAPPER AND NOT A SEALED STATEMENT
//
//   Sealing the in-toto Statement directly would mean adding `context` and
//   `evidenceDigest` as top-level members of it. The result would be neither a
//   valid Statement (two unknown top-level fields) nor an honest evidence
//   record (the digest exclusion would be operating on a schema that does not
//   know about it). So the Statement is carried WHOLE, as one member of a
//   record that obeys interfaces.md §5, and can be lifted back out byte-exact
//   by anything that wants to hand it to an in-toto consumer.
//
// FIELD ORDER
//
//   `sealRecord` writes members in the order they were authored and sorts only
//   the canonical text, so the order below is the order on disk. It is chosen
//   for reading a diff: what kind of record, then the claim, then the two
//   fields that bind it.

import { runContext } from '../../evidence/clock.mjs';
import { sealRecord } from '../../evidence/canon.mjs';
import { contextDigest } from './signing.mjs';

export const RECORD_VERSION = 'provenance-record-v0';
export const COMPONENT = 'provenance';

/**
 * Assemble and seal. The context is built first and digested into
 * `contextDigest` before sealing, because `contextDigest` is itself a digested
 * field — build it afterwards and it would be committing to a subtree the
 * digest was taken without.
 *
 * @param {{statement: Record<string, unknown>,
 *          toolchain: Record<string, unknown>,
 *          contextExtra?: Record<string, unknown>,
 *          context?: Record<string, unknown>}} args
 * @returns {Record<string, unknown>} the sealed record
 */
export function buildProvenanceRecord({ statement, toolchain, contextExtra = {}, context = null }) {
  const ctx = context ?? runContext(contextExtra);
  const record = {
    recordVersion: RECORD_VERSION,
    component: COMPONENT,
    statement,
    toolchain,
    contextDigest: contextDigest(ctx),
    context: ctx,
    evidenceDigest: null,
  };
  return sealRecord(record, { context: ctx, pathMode: 'strict', label: 'provenance record' });
}

/** Structural problems with a record read off disk. Crypto is checked elsewhere. */
export function recordProblems(rec) {
  const problems = [];
  if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) {
    return ['the record file does not hold a JSON object'];
  }
  if (rec.recordVersion !== RECORD_VERSION) {
    problems.push(`recordVersion is ${JSON.stringify(rec.recordVersion)}, expected ${RECORD_VERSION}`);
  }
  if (rec.component !== COMPONENT) {
    problems.push(`component is ${JSON.stringify(rec.component)}, expected ${COMPONENT}`);
  }
  if (rec.statement === null || typeof rec.statement !== 'object') problems.push('statement is missing');
  if (rec.toolchain === null || typeof rec.toolchain !== 'object') problems.push('toolchain is missing');
  if (!/^[0-9a-f]{64}$/.test(rec.contextDigest ?? '')) {
    problems.push('contextDigest is not 64 lowercase hex characters');
  }
  if (!/^[0-9a-f]{64}$/.test(rec.evidenceDigest ?? '')) {
    problems.push('evidenceDigest is not 64 lowercase hex characters');
  }
  if (rec.context === null || typeof rec.context !== 'object') problems.push('context is missing');
  return problems;
}

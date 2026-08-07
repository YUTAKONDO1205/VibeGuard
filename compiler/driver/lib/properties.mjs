// The property catalogue, connected to something that runs.
//
// `compiler/schema/properties.json` is a catalogue, and its own `readMeFirst`
// says why it exists: "a policy that names a property with no reachable
// checkpoint has to be exit 3, and a caller can only know that if this file
// says which properties those are." Until now nothing in the driver opened it,
// and `policy.properties[]` had no consumer at all — a policy could demand five
// properties nothing in this tree can observe and the build exited 0.
//
// THE THREE STATUS VALUES, AND THE FOURTH
//
// The catalogue declares three: `implemented`, `candidate`, `unimplemented`.
// Only `implemented` means "an extractor exists AND a fixture in this
// repository measures this property in this configuration". `candidate` is
// explicitly "nothing here has measured it, so nobody should quote it as
// evidence" — which is precisely the thing a policy is doing when it names the
// property, so `candidate` is not usable either. A status outside the declared
// three is treated the same way and reported by name, because a catalogue that
// has grown a vocabulary its own preamble does not list is a catalogue the
// driver cannot interpret, and guessing is how a check becomes a claim.
//
// EMPTY IS NOT "ALL REQUIREMENTS MET"
//
// `properties: []` is legal. It is not a pass. The record says `requested: 0`
// and carries a `claim` string saying in words that nothing was requested and
// therefore nothing was met. `properties` absent is a *different* state again
// (`configured: false`) and is recorded as itself: "the policy never raised the
// question" and "the policy raised it and listed nothing" are two facts and
// collapsing them is how an empty scan becomes a green tick.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CFG, makeFinding } from './findings.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export const CATALOGUE_PATH = resolve(HERE, '..', '..', 'schema', 'properties.json');

/** How the catalogue is named in a record. Never an absolute path (§5). */
export const CATALOGUE_RECORD_PATH = 'schema/properties.json';

export const CATALOGUE_VERSION = 'properties-v0';

/** The vocabulary the catalogue's own preamble declares. */
export const DECLARED_STATUSES = Object.freeze(['implemented', 'candidate', 'unimplemented']);

/** The single status that means a policy may rely on the property. */
export const USABLE_STATUS = 'implemented';

/**
 * Read and shape-check the catalogue.
 *
 * @returns {{ok: true, catalogue: object} | {ok: false, reason: string, detail: string}}
 */
export function loadCatalogue(path = CATALOGUE_PATH) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    // The errno, not the message: an fs message carries the absolute path it
    // failed on and this reason is quoted into a finding.
    return { ok: false, reason: 'unreadable', detail: err.code ?? 'read failed' };
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');

  let raw;
  try {
    raw = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    return { ok: false, reason: 'not-json', detail: err.message };
  }
  if (raw?.schemaVersion !== CATALOGUE_VERSION) {
    return {
      ok: false,
      reason: 'bad-version',
      detail: `expected schemaVersion ${CATALOGUE_VERSION}, got ${JSON.stringify(raw?.schemaVersion)}`,
    };
  }
  if (!Array.isArray(raw.properties) || raw.properties.length === 0) {
    return { ok: false, reason: 'no-properties', detail: 'the catalogue lists no properties; it cannot answer anything' };
  }

  const byId = new Map();
  for (const entry of raw.properties) {
    if (typeof entry?.id !== 'string' || typeof entry?.kind !== 'string' || typeof entry?.status !== 'string') {
      return { ok: false, reason: 'bad-entry', detail: `a catalogue entry is missing id, kind or status: ${JSON.stringify(entry?.id ?? entry)}` };
    }
    const checkpoints = Array.isArray(entry.observeAt) ? entry.observeAt : [];
    byId.set(entry.id, {
      id: entry.id,
      kind: entry.kind,
      status: entry.status,
      extractor: typeof entry.extractor === 'string' ? entry.extractor : null,
      checkpoints: checkpoints.map((c) => ({
        checkpoint: typeof c?.checkpoint === 'string' ? c.checkpoint : null,
        status: typeof c?.status === 'string' ? c.status : 'unimplemented',
        extractor: typeof c?.extractor === 'string' ? c.extractor : null,
      })),
    });
  }

  const kindCoverage = (raw.kindCoverage && typeof raw.kindCoverage === 'object') ? raw.kindCoverage : {};

  return {
    ok: true,
    catalogue: {
      schemaVersion: raw.schemaVersion,
      sha256,
      entryCount: byId.size,
      byId,
      kindCoverage,
    },
  };
}

/**
 * A kind whose catalogue-level coverage line begins "none" has no extractor at
 * all, whatever an individual entry claims. Read as a prefix rather than by
 * equality because the lines are prose ("none -- no extractor, no checkpoint,
 * no measurement").
 */
export function kindHasAnyImplementation(catalogue, kind) {
  const line = catalogue.kindCoverage?.[kind];
  if (typeof line !== 'string' || line.trim().length === 0) return false;
  return !/^none\b/i.test(line.trim());
}

/**
 * Cross-check `policy.properties[]` against the catalogue.
 *
 * @param {Array|undefined} policyProperties `policy.properties`, possibly absent.
 * @param {object} catalogue from {@link loadCatalogue}.
 * @returns {{configured: boolean, requested: number, checked: number, skipped: number,
 *            usable: number, unanswerable: number, complete: boolean, verdict: string,
 *            claim: string, entries: object[], findings: object[]}}
 */
export function checkProperties(policyProperties, catalogue) {
  const configured = Array.isArray(policyProperties);
  const list = configured ? policyProperties : [];
  const entries = [];
  const findings = [];
  let usable = 0;
  let checked = 0;

  for (const raw of list) {
    const id = typeof raw?.id === 'string' ? raw.id : null;
    const kind = typeof raw?.kind === 'string' ? raw.kind : null;
    const askedFor = Array.isArray(raw?.observeAt) ? raw.observeAt.filter((c) => typeof c === 'string') : [];
    checked += 1;

    const record = {
      id: id ?? '(missing id)',
      kind: kind ?? '(missing kind)',
      catalogueKind: null,
      catalogueStatus: null,
      requestedCheckpoints: askedFor,
      reachableCheckpoints: [],
      verdict: 'reachable',
    };

    const cat = id === null ? undefined : catalogue.byId.get(id);

    if (!cat) {
      record.verdict = 'unknown-id';
      entries.push(record);
      findings.push(makeFinding({
        id: CFG.PROPERTY_NOT_IN_CATALOGUE,
        severity: 'high',
        title: 'The policy names a property the catalogue does not define',
        detail: `${record.id} is not in ${CATALOGUE_RECORD_PATH} (${catalogue.entryCount} entries). `
          + 'A property nothing defines cannot be observed, so this build has not been checked for it.',
        where: { kind: 'invocation', path: null, unit: null, pass: null },
      }));
      continue;
    }

    record.catalogueKind = cat.kind;
    record.catalogueStatus = cat.status;

    if (cat.kind !== kind) {
      record.verdict = 'kind-mismatch';
      entries.push(record);
      findings.push(makeFinding({
        id: CFG.PROPERTY_KIND_MISMATCH,
        severity: 'high',
        title: 'The policy asks for a property under a different kind than the catalogue defines',
        detail: `${record.id}: the policy says ${record.kind}, the catalogue says ${cat.kind}. `
          + 'The kind decides which extractor answers the question, so the two disagreeing means nobody answered it.',
        where: { kind: 'invocation', path: null, unit: null, pass: null },
      }));
      continue;
    }

    let reason = null;
    if (!kindHasAnyImplementation(catalogue, cat.kind)) {
      record.verdict = 'kind-unimplemented';
      reason = `the catalogue's coverage line for the kind ${cat.kind} is "none": no extractor, no checkpoint, no measurement`;
    } else if (!DECLARED_STATUSES.includes(cat.status)) {
      record.verdict = 'status-not-in-vocabulary';
      reason = `the catalogue gives ${record.id} the status ${JSON.stringify(cat.status)}, which is not one of `
        + `${DECLARED_STATUSES.join(', ')}; the driver will not guess what a status it cannot read is worth`;
    } else if (cat.status !== USABLE_STATUS) {
      record.verdict = `property-${cat.status}`;
      reason = cat.status === 'candidate'
        ? `the catalogue marks ${record.id} candidate: an extractor would take this configuration but nothing here has `
          + 'measured it, and the catalogue says such a property must not be quoted as evidence'
        : `the catalogue marks ${record.id} unimplemented: there is no extractor for it`;
    } else {
      const implemented = cat.checkpoints.filter((c) => c.status === USABLE_STATUS && c.extractor !== null && c.checkpoint !== null);
      const wanted = askedFor.length > 0
        ? implemented.filter((c) => askedFor.includes(c.checkpoint))
        : implemented;
      record.reachableCheckpoints = wanted.map((c) => c.checkpoint);
      if (wanted.length === 0) {
        record.verdict = 'no-reachable-checkpoint';
        reason = askedFor.length > 0
          ? `${record.id} has no implemented extractor at any of the checkpoints the policy asked for `
            + `(${askedFor.join(', ')}); the catalogue implements it at `
            + `${implemented.map((c) => c.checkpoint).join(', ') || 'no checkpoint at all'}`
          : `${record.id} has no implemented extractor at any checkpoint`;
      }
    }

    entries.push(record);
    if (reason === null) {
      usable += 1;
      continue;
    }
    findings.push(makeFinding({
      id: CFG.PROPERTY_NOT_OBSERVABLE,
      severity: 'medium',
      title: 'The policy requires a property that has no reachable checkpoint',
      detail: `${reason}. policy.schema.json fixes the answer for this case: exit 3, not a pass.`,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }

  const unanswerable = checked - usable;
  let verdict;
  let claim;
  if (!configured) {
    verdict = 'not-configured';
    claim = 'the policy declares no properties[]; no security property was requested, checked, or claimed to hold';
  } else if (checked === 0) {
    verdict = 'no-properties-requested';
    claim = 'the policy declares properties[] and it is empty: requested=0. Legal, and not a statement '
      + 'that any requirement was met — nothing was asked, so nothing was answered';
  } else if (unanswerable > 0) {
    verdict = 'not-all-requested-reachable';
    claim = `${unanswerable} of ${checked} requested propert${checked === 1 ? 'y' : 'ies'} has no reachable checkpoint`;
  } else {
    verdict = 'all-requested-reachable';
    claim = `all ${checked} requested propert${checked === 1 ? 'y is' : 'ies are'} defined by the catalogue and have `
      + 'an implemented extractor at a requested checkpoint';
  }

  return {
    configured,
    requested: checked,
    checked,
    // Nothing is skipped: a property the driver cannot answer is a finding, not
    // a skip. The counter exists so that the counting line can state the zero
    // rather than leave the reader to assume it.
    skipped: 0,
    usable,
    unanswerable,
    complete: findings.length === 0,
    verdict,
    claim,
    entries,
    findings,
  };
}

/** The finding raised when the catalogue itself cannot be read. */
export function catalogueUnreadableFinding(load) {
  return makeFinding({
    id: CFG.PROPERTY_CATALOGUE_UNREADABLE,
    severity: 'high',
    title: 'The property catalogue could not be read, so no property could be cross-checked',
    detail: `${CATALOGUE_RECORD_PATH}: ${load.reason} (${load.detail}). `
      + 'Without it the driver cannot tell an implemented property from an unimplemented one, and it will not assume.',
    where: { kind: 'invocation', path: null, unit: null, pass: null },
  });
}

/**
 * `inputs=N checked=N skipped=S`, the one line every runner here prints.
 *
 * `requested` is accepted as a spelling of `inputs` so that a `checkProperties`
 * result can be handed over whole. A missing count prints as 0 and never as
 * `undefined`: a counting line whose job is to make an empty scan visible must
 * not itself be the thing that goes blank.
 */
export function countingLine(counts = {}) {
  const n = (v) => (Number.isInteger(v) ? v : 0);
  return `inputs=${n(counts.inputs ?? counts.requested)} checked=${n(counts.checked)} skipped=${n(counts.skipped)}`;
}

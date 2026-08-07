// Verification: everything that can be checked about one signed provenance
// record, in one pass, with a state per check.
//
// FINDING IDs — BANDS CLAIMED BY THIS COMPONENT
//
//   `../../evidence/README.md` set the precedent: a component takes a band of a
//   namespace so nothing else in it collides. This component takes
//
//     VG-ART-120 .. VG-ART-129   signature, digest and statement integrity
//     VG-CFG-030 .. VG-CFG-039   provenance disagreeing with the pin or the checkout
//
//   The ART band starts at 120 rather than at the next free low number because
//   several components in this directory were written concurrently and the low
//   bands filled while this one was being written; 070-079 and 080-092 were
//   taken by peers. Changing it means changing `ART` below and nothing else.
//
//   VG-CFG rather than VG-ART for the last two because interfaces.md §2 gives
//   "a toolchain digest does not match the pin" to VG-CFG explicitly. The
//   driver's own allocation ran to VG-CFG-019 when this was written.
//
// THE TWO LAYERS, AND WHY BOTH ARE NEEDED
//
//   Layer 1 is cryptographic: the signature covers the canonical text, so ANY
//   edit to any digested field — the commit sha, the toolchain digest, a
//   subject digest — invalidates it. That is what makes tampering detectable.
//
//   Layer 2 re-derives the same claims from the world: the toolchain digest is
//   recomputed from a pin file, the commit sha is compared with one the caller
//   supplies, the subject digests are recomputed from the artefacts. Layer 2 is
//   not redundant. Layer 1 fails only for an attacker WITHOUT the key. An
//   attacker who holds the key re-signs, and every layer-1 check passes on a
//   document that says whatever they wanted. Layer 2 is the only part of this
//   that survives key compromise, and it survives it exactly to the extent that
//   the verifier was given something independent to compare against — which is
//   why a run with no `--pin` and no `--expect-commit` reports those checks as
//   NOT_OBSERVED and says so out loud.
//
// STATES (interfaces.md §3)
//
//   PRESENT        the property holds at this observation point.
//   ABSENT         observed to be violated.
//   NOT_OBSERVED   not looked at — the caller did not supply what it would take.
//   NOT_APPLICABLE the question has no referent for this record.
//
//   LOST and REINTRODUCED do not appear, and their absence is a fact about the
//   observation and not an abbreviation of the vocabulary: both are defined
//   relative to an EARLIER observation of the same property, and verifying one
//   record is a single point. A caller verifying a sequence of records keeps
//   the sequence of `checks[]` arrays — never collapsing it, never stopping at
//   the first ABSENT — and derives LOST/REINTRODUCED across them.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_OK } from '../../driver/lib/exit.mjs';
import { makeFinding, atOrAboveThreshold } from '../../driver/lib/findings.mjs';
import { canonicalJson } from '../../evidence/canon.mjs';
import { contextDigest, verifyDetached, envelopeProblems } from './signing.mjs';
import { recordProblems } from './record.mjs';
import { recordedCommitSha, recordedToolchainDigest, statementProblems, subjects } from './statement.mjs';
import { declaredToolchainDigest } from './pin.mjs';

export const ART = {
  SIGNATURE_INVALID: 'VG-ART-120',
  SIGNED_OTHER_BYTES: 'VG-ART-121',
  UNTRUSTED_KEY: 'VG-ART-122',
  EVIDENCE_DIGEST_MISMATCH: 'VG-ART-123',
  CONTEXT_ALTERED: 'VG-ART-124',
  STATEMENT_INCOMPLETE: 'VG-ART-125',
  SUBJECT_BYTES_DIFFER: 'VG-ART-126',
  TOOLCHAIN_SELF_DISAGREEMENT: 'VG-ART-127',
  SIGNATURE_MALFORMED: 'VG-ART-128',
  RECORD_MALFORMED: 'VG-ART-129',
};

export const CFG = {
  TOOLCHAIN_NOT_THE_PIN: 'VG-CFG-030',
  COMMIT_NOT_THE_CHECKOUT: 'VG-CFG-031',
};

/** Findings in these classes mean the trust chain failed: exit 4, not exit 2. */
const INTEGRITY_IDS = new Set([
  ART.SIGNATURE_INVALID,
  ART.SIGNED_OTHER_BYTES,
  ART.UNTRUSTED_KEY,
  ART.EVIDENCE_DIGEST_MISMATCH,
  ART.CONTEXT_ALTERED,
  ART.SIGNATURE_MALFORMED,
  ART.RECORD_MALFORMED,
  CFG.TOOLCHAIN_NOT_THE_PIN,
]);

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Verify one record/envelope pair.
 *
 * @param {{
 *   record: unknown,
 *   envelope: unknown,
 *   trustedPublicKey: import('node:crypto').KeyObject,
 *   pin?: Record<string, unknown>|null,
 *   artifactRoot?: string|null,
 *   expectCommit?: string|null,
 *   label?: string,
 * }} args
 * @returns {{checks: object[], findings: object[]}}
 */
export function verifyProvenance(args) {
  const {
    record, envelope, trustedPublicKey,
    pin = null, artifactRoot = null, expectCommit = null,
    label = 'record',
  } = args;

  const checks = [];
  const findings = [];
  const note = (name, state, detail) => { checks.push({ detail, name, state }); };
  const fail = (id, severity, title, detail, where) => {
    findings.push(makeFinding({ id, severity, title, detail, where }));
  };

  // ---- structure -----------------------------------------------------------
  const recProblems = recordProblems(record);
  if (recProblems.length > 0) {
    note('record-shape', 'ABSENT', recProblems.join('; '));
    fail(ART.RECORD_MALFORMED, 'critical',
      'The file is not a provenance record',
      recProblems.join('\n'),
      { kind: 'artifact', path: label });
    // Everything below reads fields this record does not reliably have.
    return { checks, findings };
  }
  note('record-shape', 'PRESENT', 'recordVersion, component and the two digest fields are present');

  const envProblems = envelopeProblems(envelope);
  if (envProblems.length > 0) {
    note('signature-shape', 'ABSENT', envProblems.join('; '));
    fail(ART.SIGNATURE_MALFORMED, 'critical',
      'The detached signature is malformed',
      envProblems.join('\n'),
      { kind: 'artifact', path: label });
    return { checks, findings };
  }
  note('signature-shape', 'PRESENT', 'the envelope declares an ed25519 detached signature');

  // ---- layer 1: the signature ---------------------------------------------
  const sig = verifyDetached({ record, envelope, trustedPublicKey });
  const reason = new Set(sig.reasons);

  if (reason.has('untrusted-key')) {
    note('trusted-key', 'ABSENT',
      `signed by ${envelope.keyId}, trusted key is ${sig.details.trustedKeyId}`);
    fail(ART.UNTRUSTED_KEY, 'critical',
      'The signature was made by a key this verifier does not trust',
      `The envelope names key ${envelope.keyId}; the key supplied to the verifier is `
      + `${sig.details.trustedKeyId}. A signature checked against the key that came with it `
      + 'proves only that the document is self-consistent, which a forgery also is.',
      { kind: 'artifact', path: label });
  } else {
    note('trusted-key', 'PRESENT', `signed by the trusted key ${sig.details.trustedKeyId}`);
  }

  if (reason.has('canonical-digest-mismatch')) {
    note('signed-bytes', 'ABSENT',
      `envelope covers ${envelope.canonicalDigest}, the record canonicalises to ${sig.details.actualCanonicalDigest}`);
    fail(ART.SIGNED_OTHER_BYTES, 'critical',
      'The signature is over bytes this record does not produce',
      `The envelope says it covers canonical text with digest ${envelope.canonicalDigest}; the `
      + `record on disk canonicalises to ${sig.details.actualCanonicalDigest}. The record was `
      + 'edited after it was signed, or the signature belongs to a different record.',
      { kind: 'artifact', path: label });
  } else {
    note('signed-bytes', 'PRESENT', `the envelope covers this record's canonical text (${sig.details.signedBytes} B)`);
  }

  if (reason.has('signature-does-not-verify')) {
    note('signature', 'ABSENT', 'ed25519 verification failed');
    fail(ART.SIGNATURE_INVALID, 'critical',
      'The detached signature does not verify',
      'Ed25519 verification of the canonical text against the trusted public key failed. '
      + 'Either the signed bytes are not these bytes, or the signature is not this key\'s.',
      { kind: 'artifact', path: label });
  } else {
    note('signature', 'PRESENT', 'ed25519 verification succeeded against the trusted key');
  }

  if (reason.has('embedded-key-disagrees-with-its-own-id')) {
    fail(ART.SIGNATURE_MALFORMED, 'high',
      'The envelope\'s embedded public key is not the key its keyId names',
      'publicKey and keyId in the same envelope describe different keys.',
      { kind: 'artifact', path: label });
  }

  // ---- the two digests the record carries ---------------------------------
  const canonicalText = canonicalJson(record);
  const rederived = sha256Hex(Buffer.from(canonicalText, 'utf8'));
  if (rederived !== record.evidenceDigest) {
    note('evidence-digest', 'ABSENT', `carries ${record.evidenceDigest}, re-derives to ${rederived}`);
    fail(ART.EVIDENCE_DIGEST_MISMATCH, 'high',
      'evidenceDigest does not match a re-derivation',
      `The record carries ${record.evidenceDigest}; recomputing it from the canonical text gives `
      + `${rederived}.`,
      { kind: 'artifact', path: label });
  } else {
    note('evidence-digest', 'PRESENT', `re-derived ${rederived}`);
  }

  const ctxDigest = contextDigest(record.context);
  if (ctxDigest !== record.contextDigest) {
    note('context-digest', 'ABSENT', `carries ${record.contextDigest}, context digests to ${ctxDigest}`);
    fail(ART.CONTEXT_ALTERED, 'critical',
      'The context subtree has been altered since the record was sealed',
      `contextDigest is ${record.contextDigest}; the context in this file digests to ${ctxDigest}. `
      + 'context is excluded from the evidence digest by interfaces.md §5 rule 1, so this field is '
      + 'the only thing that binds it — an edit to generatedAt or to the host block moves nothing '
      + 'else in the record.',
      { kind: 'artifact', path: label });
  } else {
    note('context-digest', 'PRESENT', 'the context subtree is the one that was sealed');
  }

  // ---- layer 1b: is the statement a complete provenance document? ---------
  const stProblems = statementProblems(record.statement);
  if (stProblems.length > 0) {
    note('statement-fields', 'ABSENT', `${stProblems.length} problem(s)`);
    fail(ART.STATEMENT_INCOMPLETE, 'high',
      'The provenance statement is missing a required field',
      stProblems.join('\n'),
      { kind: 'artifact', path: label });
  } else {
    note('statement-fields', 'PRESENT', 'subject, builder.id, buildType, invocation and materials are all present');
  }

  const stToolchain = recordedToolchainDigest(record.statement);
  const blockToolchain = record.toolchain?.digest ?? null;
  if (stToolchain === null || blockToolchain === null) {
    note('toolchain-self-agreement', 'NOT_APPLICABLE',
      'the record does not carry a toolchain digest in both places');
  } else if (stToolchain !== blockToolchain) {
    note('toolchain-self-agreement', 'ABSENT', `${stToolchain} in materials, ${blockToolchain} in toolchain`);
    fail(ART.TOOLCHAIN_SELF_DISAGREEMENT, 'high',
      'The record states two different toolchain digests',
      `predicate.materials names ${stToolchain}; the record's toolchain block says `
      + `${blockToolchain}. One of them is not the toolchain this was built with.`,
      { kind: 'artifact', path: label });
  } else {
    note('toolchain-self-agreement', 'PRESENT', `both places say ${stToolchain}`);
  }

  // ---- layer 2: re-derive from the world ----------------------------------
  if (pin === null) {
    note('toolchain-matches-pin', 'NOT_OBSERVED',
      'no pin was supplied; the recorded toolchain digest was not compared against one');
  } else {
    const declared = declaredToolchainDigest(pin);
    if (stToolchain !== declared) {
      note('toolchain-matches-pin', 'ABSENT', `record says ${stToolchain}, pin declares ${declared}`);
      fail(CFG.TOOLCHAIN_NOT_THE_PIN, 'critical',
        'The provenance records a toolchain digest that is not the pin\'s',
        `The statement's toolchain-pin material is ${stToolchain}; the pin supplied to the `
        + `verifier declares ${declared}. The build was not done with the pinned toolchain, or the `
        + 'record is describing a different one.',
        { kind: 'invocation', path: label });
    } else {
      note('toolchain-matches-pin', 'PRESENT', `the pin declares ${declared}`);
    }
  }

  if (expectCommit === null) {
    note('commit-matches-checkout', 'NOT_OBSERVED',
      'no expected commit was supplied; the recorded commit sha was not compared against one');
  } else {
    const got = recordedCommitSha(record.statement);
    if (got !== expectCommit) {
      note('commit-matches-checkout', 'ABSENT', `record says ${got}, expected ${expectCommit}`);
      fail(CFG.COMMIT_NOT_THE_CHECKOUT, 'high',
        'The provenance records a commit that is not the one it was checked against',
        `configSource.digest.sha1 is ${got}; the commit supplied to the verifier is ${expectCommit}.`,
        { kind: 'invocation', path: label });
    } else {
      note('commit-matches-checkout', 'PRESENT', `configSource.digest.sha1 is ${got}`);
    }
  }

  if (artifactRoot === null) {
    note('subject-bytes', 'NOT_OBSERVED',
      'no artefact root was supplied; subject digests were not compared against any bytes');
  } else {
    const subs = subjects(record.statement);
    let bad = 0;
    let unreadable = 0;
    for (const s of subs) {
      let actual = null;
      // A subject name is a path out of a document that may be hostile. It is
      // resolved under the artefact root and nowhere else: an absolute name, or
      // one that climbs out with `..`, would make the verifier hash a file the
      // caller never offered it.
      const escapes = typeof s.name !== 'string'
        || s.name.length === 0
        || /^([A-Za-z]:[\\/]|[\\/])/.test(s.name)
        || s.name.split(/[\\/]/).includes('..');
      if (escapes) {
        unreadable += 1;
        fail(ART.SUBJECT_BYTES_DIFFER, 'high',
          'A subject name does not resolve under the artefact root',
          `subject ${JSON.stringify(s.name)} is absolute or climbs out of the root supplied; it was `
          + 'not read. Subject names are relative to the fixture root (interfaces.md §5).',
          { kind: 'artifact', path: null });
        continue;
      }
      try {
        actual = sha256Hex(readFileSync(join(artifactRoot, s.name)));
      } catch {
        unreadable += 1;
        fail(ART.SUBJECT_BYTES_DIFFER, 'high',
          'A subject named by the provenance could not be read',
          `subject ${JSON.stringify(s.name)} is not readable under the artefact root supplied. `
          + 'A subject that is not there has not been checked, and is not evidence of anything.',
          { kind: 'artifact', path: s.name });
        continue;
      }
      if (actual !== s.sha256) {
        bad += 1;
        fail(ART.SUBJECT_BYTES_DIFFER, 'high',
          'A subject\'s bytes do not match the digest the provenance records',
          `subject ${JSON.stringify(s.name)} hashes to ${actual}; the statement records ${s.sha256}.`,
          { kind: 'artifact', path: s.name });
      }
    }
    if (bad === 0 && unreadable === 0) {
      note('subject-bytes', 'PRESENT', `${subs.length} subject(s) matched their recorded digests`);
    } else {
      note('subject-bytes', 'ABSENT', `${bad} mismatched, ${unreadable} unreadable, of ${subs.length}`);
    }
  }

  return { checks, findings };
}

/**
 * Turn findings and states into one exit code.
 *
 * PRECEDENCE, stated because it is a decision and not an accident:
 *   4 integrity  the trust chain failed. Nothing else about the record means
 *                anything, so it outranks everything.
 *   3 incomplete something the caller asked for could not be looked at. It
 *                outranks 2 because findings drawn from a partially-checked set
 *                are not a verdict about the set — the findings are still
 *                printed either way.
 *   2 findings   the record verified, and disagrees with the world.
 *   0 clean.
 *
 * @param {{findings: object[], checks: object[], failOn?: string, strict?: boolean,
 *          incomplete?: boolean}} args
 */
export function exitCodeFor({ findings, checks, failOn = 'low', strict = false, incomplete = false }) {
  if (findings.some((f) => INTEGRITY_IDS.has(f.id))) return EXIT_INTEGRITY;
  const notObserved = checks.filter((c) => c.state === 'NOT_OBSERVED');
  if (incomplete) return EXIT_INCOMPLETE;
  if (strict && notObserved.length > 0) return EXIT_INCOMPLETE;
  if (atOrAboveThreshold(findings, failOn).length > 0) return EXIT_FINDINGS;
  return EXIT_OK;
}

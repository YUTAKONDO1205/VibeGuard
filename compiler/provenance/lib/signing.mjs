// Detached signatures over the canonical evidence form.
//
// WHAT IS SIGNED, AND WHY IT IS NOT THE FILE
//
//   The signed bytes are `canonicalJson(record)` — the same text
//   `evidenceDigest` is taken over (interfaces.md §5, rules 1-5). Not the file
//   on disk. Two reasons, and the second one is the one that matters:
//
//     * the file is pretty-printed, so a reformat, a line-ending conversion or
//       a re-serialisation with the keys in a different order would break a
//       signature over the raw bytes while changing nothing that was claimed;
//     * a signature over the canonical form signs the same thing the digest
//       commits to, so "the signature verifies" and "the digest matches" cannot
//       come apart. If they were over different inputs there would be two
//       notions of "this record", and a checker holding two of those is a
//       checker that can be made to disagree with itself.
//
// THE HOLE THAT CREATES, AND HOW IT IS CLOSED
//
//   Rule 1 removes the top-level `context` subtree before digesting. That is
//   deliberate — `context` is where everything a re-run cannot reproduce lives
//   — but it means a signature over the canonical text says NOTHING about
//   `context`. Anyone could edit `generatedAt`, or the host block, and both the
//   digest and the signature would still check out.
//
//   So the record carries `contextDigest`, a top-level field which IS digested
//   and which is the SHA-256 of the canonical text of the `context` subtree.
//   The excluded subtree is thereby committed to by an included field, the
//   exclusion rule is untouched, and editing `context` after the fact is caught
//   — by `verify-core.mjs`, as VG-ART-124. This is the only way the two
//   requirements ("volatile fields are not digested" and "nothing in the file
//   is unsigned") can both hold.
//
// WHAT A SIGNATURE HERE DOES NOT PROVE
//
//   That the claims are true. It proves that the holder of one private key
//   asserted them. Everything the verifier can re-derive from the world — the
//   artefact bytes, the toolchain pin, the commit — it re-derives, precisely
//   because a signature over a false statement is a valid signature.

import { createHash, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import { canonicalJson, canonicalJsonRaw } from '../../evidence/canon.mjs';
import { keyId, publicKeyFromBase64, publicKeyToBase64 } from './keys.mjs';

export const SIG_VERSION = 'detached-sig-v0';
export const PAYLOAD_KIND = 'evidence-canonical-text';

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * The bytes a signature is taken over: the canonical text of the record, UTF-8.
 *
 * @param {Record<string, unknown>} record
 * @returns {Buffer}
 */
export function signingBytes(record) {
  return Buffer.from(canonicalJson(record), 'utf8');
}

/**
 * The digest of a `context` subtree, for the `contextDigest` field.
 * `canonicalJsonRaw` and not `canonicalJson`: the exclusion rule applies to the
 * top level of a RECORD, and `context` here is an ordinary value being hashed
 * whole.
 *
 * @param {unknown} context
 * @returns {string}
 */
export function contextDigest(context) {
  return sha256Hex(Buffer.from(canonicalJsonRaw(context), 'utf8'));
}

/**
 * Produce the detached envelope. Nothing is written; the caller decides where.
 *
 * `subjectFile` names the record this signature belongs to, relative to
 * wherever the pair is stored. It sits in the envelope, which is not itself
 * signed, so it is a convenience for locating the record and is never trusted:
 * the verifier is told which record to read and reads that one.
 *
 * @param {{record: Record<string, unknown>,
 *          privateKey: import('node:crypto').KeyObject,
 *          publicKey: import('node:crypto').KeyObject,
 *          subjectFile?: string|null}} args
 */
export function signRecord({ record, privateKey, publicKey, subjectFile = null }) {
  const bytes = signingBytes(record);
  // Ed25519 in Node takes a null digest algorithm: the scheme hashes internally
  // and passing one is an error rather than a preference.
  const signature = cryptoSign(null, bytes, privateKey);
  return {
    algorithm: 'ed25519',
    canonicalDigest: sha256Hex(bytes),
    keyId: keyId(publicKey),
    payload: { bytes: bytes.length, kind: PAYLOAD_KIND },
    publicKey: publicKeyToBase64(publicKey),
    signature: signature.toString('base64'),
    sigVersion: SIG_VERSION,
    subject: {
      evidenceDigest: typeof record.evidenceDigest === 'string' ? record.evidenceDigest : null,
      file: subjectFile,
    },
  };
}

/** Shape check on an envelope read off disk, before any crypto is attempted. */
export function envelopeProblems(env) {
  const problems = [];
  if (env === null || typeof env !== 'object' || Array.isArray(env)) {
    return ['the signature file does not hold a JSON object'];
  }
  if (env.sigVersion !== SIG_VERSION) {
    problems.push(`sigVersion is ${JSON.stringify(env.sigVersion)}, expected ${SIG_VERSION}`);
  }
  if (env.algorithm !== 'ed25519') {
    problems.push(`algorithm is ${JSON.stringify(env.algorithm)}, expected ed25519`);
  }
  if (typeof env.signature !== 'string' || env.signature.length === 0) {
    problems.push('signature is missing');
  }
  if (typeof env.publicKey !== 'string' || env.publicKey.length === 0) {
    problems.push('publicKey is missing');
  }
  if (!/^[0-9a-f]{64}$/.test(env.keyId ?? '')) {
    problems.push('keyId is not 64 lowercase hex characters');
  }
  if (!/^[0-9a-f]{64}$/.test(env.canonicalDigest ?? '')) {
    problems.push('canonicalDigest is not 64 lowercase hex characters');
  }
  if (env.payload?.kind !== PAYLOAD_KIND) {
    problems.push(`payload.kind is ${JSON.stringify(env.payload?.kind)}, expected ${PAYLOAD_KIND}`);
  }
  return problems;
}

/**
 * Check a detached envelope against a record and a TRUSTED public key.
 *
 * The trusted key is a required argument and there is no code path that falls
 * back to the key inside the envelope. A verifier that trusts the key shipped
 * next to the signature checks that a document is self-consistent, which every
 * forgery also is.
 *
 * @param {{record: Record<string, unknown>,
 *          envelope: Record<string, unknown>,
 *          trustedPublicKey: import('node:crypto').KeyObject}} args
 * @returns {{ok: boolean, reasons: string[], details: Record<string, unknown>}}
 */
export function verifyDetached({ record, envelope, trustedPublicKey }) {
  const reasons = [];
  const shape = envelopeProblems(envelope);
  if (shape.length > 0) {
    return { ok: false, reasons: shape.map((p) => `malformed:${p}`), details: {} };
  }

  const trustedId = keyId(trustedPublicKey);
  // THE TRUST ANCHOR. The envelope names a key; the caller supplies the key it
  // is willing to believe. If those differ, nothing else about the envelope
  // matters — a forger signs with their own key and writes it here.
  const keyMatches = envelope.keyId === trustedId;
  if (!keyMatches) reasons.push('untrusted-key');

  let embeddedMatchesTrusted = false;
  try {
    embeddedMatchesTrusted = keyId(publicKeyFromBase64(envelope.publicKey)) === envelope.keyId;
  } catch {
    embeddedMatchesTrusted = false;
  }
  if (!embeddedMatchesTrusted) reasons.push('embedded-key-disagrees-with-its-own-id');

  const bytes = signingBytes(record);
  const actualCanonicalDigest = sha256Hex(bytes);
  if (envelope.canonicalDigest !== actualCanonicalDigest) reasons.push('canonical-digest-mismatch');

  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(null, bytes, trustedPublicKey, Buffer.from(envelope.signature, 'base64'));
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) reasons.push('signature-does-not-verify');

  return {
    ok: reasons.length === 0,
    reasons,
    details: {
      actualCanonicalDigest,
      envelopeCanonicalDigest: envelope.canonicalDigest,
      signedBytes: bytes.length,
      trustedKeyId: trustedId,
      envelopeKeyId: envelope.keyId,
    },
  };
}

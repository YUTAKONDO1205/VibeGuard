// Key material for detached evidence signatures.
//
// KEY MANAGEMENT IS NOT THE CONTRIBUTION, AND SAYING SO IS PART OF THE DESIGN
//
//   What is being demonstrated here is that a record can be bound to a signer
//   and that any edit to the record breaks the binding. Where the signing key
//   lives, who is allowed to hold it, and how it is rotated are a deployment
//   question with well-known answers (an HSM, a KMS, a short-lived workload
//   identity), none of which this directory is in a position to provide and
//   none of which would make the mechanism below more or less correct.
//
//   So the key pair is generated locally, on demand, into a directory the
//   caller names. No private key is committed, and none is generated into the
//   source tree by default. `README.md` states plainly what an attacker who
//   holds the private key can do, which is: everything the signer can do. The
//   defence against that is not in this file — it is the set of claims the
//   verifier RE-DERIVES from the world instead of reading out of the signed
//   document.
//
// WHY Ed25519
//
//   Deterministic signatures (RFC 8032): the same key over the same message
//   produces the same 64 bytes every time. A signature that changed on every
//   run would make a signed record non-reproducible, which is the opposite of
//   what the rest of this toolchain is for. ECDSA would need RFC 6979 to get
//   the same property and Node does not offer it.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const KEY_ALGORITHM = 'ed25519';

/**
 * The identifier a verifier compares. SHA-256 over the DER of the SubjectPublicKeyInfo,
 * lowercase hex — the public key's own bytes, not a filename and not a label,
 * so two files holding the same key have the same id and a renamed key does not
 * become a different one.
 *
 * @param {import('node:crypto').KeyObject} publicKey
 * @returns {string} 64 lowercase hex characters
 */
export function keyId(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

/**
 * Generate a fresh pair in memory. Nothing is written; the caller decides
 * where — and in the tests the answer is a temporary directory that is removed
 * afterwards.
 *
 * @returns {{publicKey: import('node:crypto').KeyObject,
 *            privateKey: import('node:crypto').KeyObject,
 *            publicPem: string, privatePem: string, keyId: string}}
 */
export function generateSigningKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync(KEY_ALGORITHM);
  return {
    publicKey,
    privateKey,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    keyId: keyId(publicKey),
  };
}

/**
 * Write a pair as two PEM files under `dir`. The private file is created with
 * owner-only permissions where the platform has them; on Windows `chmod` is a
 * no-op and the returned `privateModeApplied` says so rather than implying a
 * protection that is not there.
 *
 * @param {string} dir
 * @param {{name?: string}} [opts]
 */
export function writeKeyPair(dir, opts = {}) {
  const name = opts.name ?? 'signing-key';
  mkdirSync(dir, { recursive: true });
  const pair = generateSigningKeyPair();
  const privatePath = join(dir, `${name}.pem`);
  const publicPath = join(dir, `${name}.pub.pem`);
  writeFileSync(privatePath, pair.privatePem, 'utf8');
  writeFileSync(publicPath, pair.publicPem, 'utf8');
  let privateModeApplied = false;
  try {
    chmodSync(privatePath, 0o600);
    privateModeApplied = process.platform !== 'win32';
  } catch {
    privateModeApplied = false;
  }
  return { ...pair, privatePath, publicPath, privateModeApplied };
}

/** @param {string} path */
export function loadPublicKey(path) {
  const pem = readFileSync(path, 'utf8');
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== KEY_ALGORITHM) {
    throw new Error(`expected an ${KEY_ALGORITHM} public key, got ${key.asymmetricKeyType}`);
  }
  return key;
}

/** @param {string} path */
export function loadPrivateKey(path) {
  const pem = readFileSync(path, 'utf8');
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== KEY_ALGORITHM) {
    throw new Error(`expected an ${KEY_ALGORITHM} private key, got ${key.asymmetricKeyType}`);
  }
  return key;
}

/** A public key from its base64 SPKI DER, as carried inside a signature envelope. */
export function publicKeyFromBase64(b64) {
  const der = Buffer.from(b64, 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== KEY_ALGORITHM) {
    throw new Error(`expected an ${KEY_ALGORITHM} public key, got ${key.asymmetricKeyType}`);
  }
  return key;
}

/** Base64 SPKI DER of a public key. */
export function publicKeyToBase64(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

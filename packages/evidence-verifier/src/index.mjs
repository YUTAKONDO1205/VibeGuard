// The verifying half of the evidence-carrying artefact pair.
//
// Nothing under `src/` imports the generator package, and that is the whole
// design: two sides that share an implementation agree by construction, so a
// verifier built on its generator's canonicaliser proves nothing about any
// record. The only thing the two sides share is the CONTRACT — the digest
// vectors — and `calibrate()` is what proves each side reproduces it.

export {
  MalformedRecordError,
  canonicalisationProblems,
  rederiveCanonicalText,
  rederiveCanonicalTextRaw,
  rederiveDigest,
  sha256Hex,
} from './rederive.mjs';

export {
  BUNDLE_SCHEMA_VERSION,
  BUNDLE_SELF_DIGEST_KEY,
  EVIDENCE_FILE,
  LIMITS,
  MANIFEST_FILE,
  RECORD_SCHEMA_VERSION,
  SEVERITY_ORDER,
  VERDICT,
  findBundleDirs,
  verifyBundle,
  worstSeverity,
} from './verify-bundle.mjs';

export {
  CONTRACT_BASENAME,
  COPY_FLOOR,
  ContractScanError,
  committablePaths,
  compareContractCopies,
  fingerprintFile,
  repoRootFrom,
} from './contract-copies.mjs';

export {
  FenceProbeError,
  OUR_PACKAGES,
  OUR_TOKENS,
  PACKAGE_LIST,
  PACKAGING_SCRIPT,
  TOKEN_LIST,
  arrayLiteralEntries,
  probeFence,
  probeFenceAt,
  remedyFor,
} from './fence-probe.mjs';

export { EXIT, countingLine, emptyScanVerdict, reportCounts } from './counting.mjs';

export {
  VECTORS_EXPECTED,
  VECTORS_FILE,
  VECTORS_FINGERPRINT,
  VectorsError,
  fingerprintVectors,
  loadVectors,
} from './vectors.mjs';

export { calibrate } from './calibrate.mjs';

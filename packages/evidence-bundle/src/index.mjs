// The generator half of the evidence-carrying artefact pair.
//
// Nothing here reaches outside this package. It has no dependencies at all —
// not on the other half, not on the toolchain workspace, not on the registry —
// which is what lets the verifier next door be genuinely independent of it and
// what keeps this directory out of every shipped bundle by having nothing in
// it that a browser or an editor could ever want.

export {
  CANON_RULES,
  CanonError,
  EXCLUDED_TOP_LEVEL_KEYS,
  canonicalText,
  canonicalTextRaw,
  compareCodeUnits,
  digestExcludingSelf,
  evidenceDigest,
  isArrayIndexKey,
  sha256Hex,
} from './canon.mjs';

export {
  ARTIFACT_DIR,
  BUNDLE_SCHEMA_VERSION,
  BUNDLE_SELF_DIGEST_KEY,
  BundleError,
  EVIDENCE_FILE,
  MANIFEST_FILE,
  RECORD_SCHEMA_VERSION,
  buildManifest,
  contextDigestOf,
  fileDigest,
  fileEntries,
  isDirectory,
  listBundleFiles,
  runContext,
  sealRecord,
  writeBundle,
} from './bundle.mjs';

export {
  PROPERTY_STATES,
  StateHistoryError,
  VERDICTS,
  assertStatesAreSane,
  checkOracle,
  effectiveState,
  stateHistory,
} from './states.mjs';

export { AbsolutePathError, assertNoAbsolutePaths, findAbsolutePaths } from './paths.mjs';

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

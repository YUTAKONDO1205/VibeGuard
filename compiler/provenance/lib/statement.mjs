// Build provenance in the SLSA shape.
//
// WHICH SLSA SHAPE, AND WHY THE OLDER ONE
//
//   An in-toto Statement carrying a `slsa.dev/provenance/v0.2` predicate. v0.2
//   is chosen over v1 because v0.2 is the version whose field names are
//   `builder.id`, `invocation` and `materials` — the four things this package
//   is required to record are named directly in it. v1 renames them into
//   `buildDefinition.externalParameters` and `resolvedDependencies`, which is a
//   better model and a worse match for a claim that has to be checked field by
//   field. Nothing here depends on the choice; `PREDICATE_TYPE` is the only
//   place it is written down.
//
// THE FIELDS AND WHAT EACH ONE IS FOR
//
//   subject[]              what was built, by relative name and sha256.
//   predicate.builder.id   who built it. A URN, not an https URI: this builder
//                          is a local process with no hosted identity, and
//                          minting a URL for it would assert an authority that
//                          does not exist. A URN says "a name, not a location".
//   predicate.buildType    what kind of build this was; fixes the meaning of
//                          `invocation.parameters` for a reader.
//   predicate.invocation   configSource (repository, COMMIT SHA, entry point),
//                          parameters (the argv and the compile flags),
//                          environment (platform, arch, SOURCE_DATE_EPOCH).
//   predicate.materials[]  every input that was digested: the toolchain pin,
//                          the sources. The TOOLCHAIN DIGEST lives here, in the
//                          material whose uri is `TOOLCHAIN_MATERIAL_URI`.
//   predicate.metadata     completeness, and whether a rebuild was observed to
//                          reproduce. `reproducible: null` means not observed,
//                          and is never written as `false`.
//
// CONSTRAINTS THIS SHAPE INHERITS FROM interfaces.md §5
//
//   The statement is carried inside an evidence record, so it obeys the record
//   rules: no absolute paths anywhere, every number an integer, no object key
//   that JavaScript would treat as an array index. Timestamps are NOT written
//   here — SLSA's `metadata.buildStartedOn` would be a wall-clock string inside
//   the digested region, which is exactly the field the `context` convention
//   exists to keep out of a digest. It goes into the record's `context`, and
//   `contextDigest` commits to it. That is a deliberate divergence from the
//   SLSA schema and it is listed in README.md rather than left to be found.

export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v0.1';
export const PREDICATE_TYPE = 'https://slsa.dev/provenance/v0.2';
export const DEFAULT_BUILDER_ID = 'urn:vibeguard:builder:local-compiler-toolchain:v0';
export const DEFAULT_BUILD_TYPE = 'urn:vibeguard:buildtype:pinned-clang-fixture:v0';
export const TOOLCHAIN_MATERIAL_URI = 'urn:vibeguard:material:toolchain-pin';
export const DEFAULT_CONFIG_SOURCE_URI = 'urn:vibeguard:configsource:local-checkout';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;

/**
 * @param {{
 *   subjects: {name: string, sha256: string}[],
 *   commitSha: string,
 *   toolchainDigest: string,
 *   materials?: {uri: string, sha256: string}[],
 *   builderId?: string,
 *   buildType?: string,
 *   configSourceUri?: string,
 *   entryPoint?: string,
 *   parameters?: Record<string, unknown>,
 *   environment?: Record<string, unknown>,
 *   reproducible?: boolean|null,
 * }} args
 */
export function buildStatement(args) {
  const {
    subjects,
    commitSha,
    toolchainDigest,
    materials = [],
    builderId = DEFAULT_BUILDER_ID,
    buildType = DEFAULT_BUILD_TYPE,
    configSourceUri = DEFAULT_CONFIG_SOURCE_URI,
    entryPoint = 'compiler/provenance/tools/sign-evidence.mjs',
    parameters = {},
    environment = {},
    reproducible = null,
  } = args;

  // The toolchain pin goes in first and always. A provenance document that
  // records no toolchain is a document about a build nobody can repeat, and
  // making it optional would let one be produced by leaving an argument out.
  const allMaterials = [
    { digest: { sha256: toolchainDigest }, uri: TOOLCHAIN_MATERIAL_URI },
    ...materials.map((m) => ({ digest: { sha256: m.sha256 }, uri: m.uri })),
  ];

  return {
    _type: STATEMENT_TYPE,
    predicate: {
      builder: { id: builderId },
      buildType,
      invocation: {
        configSource: {
          digest: { sha1: commitSha },
          entryPoint,
          uri: configSourceUri,
        },
        environment,
        parameters,
      },
      materials: allMaterials,
      metadata: {
        completeness: {
          environment: Object.keys(environment).length > 0,
          materials: allMaterials.length > 0,
          parameters: Object.keys(parameters).length > 0,
        },
        reproducible,
      },
    },
    predicateType: PREDICATE_TYPE,
    subject: subjects.map((s) => ({ digest: { sha256: s.sha256 }, name: s.name })),
  };
}

/**
 * Everything wrong with a statement, as a list of sentences. All of them, not
 * the first: a producer fixing one required field per run is a producer that
 * gets run five times.
 *
 * @param {unknown} st
 * @returns {string[]}
 */
export function statementProblems(st) {
  const problems = [];
  const bad = (s) => problems.push(s);

  if (st === null || typeof st !== 'object' || Array.isArray(st)) {
    return ['the provenance statement is not a JSON object'];
  }
  if (st._type !== STATEMENT_TYPE) bad(`_type is ${JSON.stringify(st._type)}, expected ${STATEMENT_TYPE}`);
  if (st.predicateType !== PREDICATE_TYPE) {
    bad(`predicateType is ${JSON.stringify(st.predicateType)}, expected ${PREDICATE_TYPE}`);
  }

  if (!Array.isArray(st.subject) || st.subject.length === 0) {
    bad('subject[] is missing or empty; provenance that names no artefact describes nothing');
  } else {
    st.subject.forEach((s, i) => {
      if (typeof s?.name !== 'string' || s.name.length === 0) bad(`subject[${i}].name is missing`);
      if (!HEX64.test(s?.digest?.sha256 ?? '')) bad(`subject[${i}].digest.sha256 is not 64 lowercase hex`);
    });
  }

  const p = st.predicate;
  if (p === null || typeof p !== 'object' || Array.isArray(p)) {
    bad('predicate is missing');
    return problems;
  }
  if (typeof p.builder?.id !== 'string' || p.builder.id.length === 0) bad('predicate.builder.id is missing');
  if (typeof p.buildType !== 'string' || p.buildType.length === 0) bad('predicate.buildType is missing');

  const inv = p.invocation;
  if (inv === null || typeof inv !== 'object' || Array.isArray(inv)) {
    bad('predicate.invocation is missing');
  } else {
    if (typeof inv.configSource?.uri !== 'string') bad('predicate.invocation.configSource.uri is missing');
    if (typeof inv.configSource?.entryPoint !== 'string') bad('predicate.invocation.configSource.entryPoint is missing');
    if (!HEX40.test(inv.configSource?.digest?.sha1 ?? '')) {
      bad('predicate.invocation.configSource.digest.sha1 is not a 40-hex commit sha');
    }
    if (inv.parameters === null || typeof inv.parameters !== 'object') bad('predicate.invocation.parameters is missing');
    if (inv.environment === null || typeof inv.environment !== 'object') bad('predicate.invocation.environment is missing');
  }

  if (!Array.isArray(p.materials) || p.materials.length === 0) {
    bad('predicate.materials[] is missing or empty');
  } else {
    p.materials.forEach((m, i) => {
      if (typeof m?.uri !== 'string' || m.uri.length === 0) bad(`predicate.materials[${i}].uri is missing`);
      if (!HEX64.test(m?.digest?.sha256 ?? '')) bad(`predicate.materials[${i}].digest.sha256 is not 64 lowercase hex`);
    });
    if (!p.materials.some((m) => m?.uri === TOOLCHAIN_MATERIAL_URI)) {
      bad(`predicate.materials[] does not include ${TOOLCHAIN_MATERIAL_URI}`);
    }
  }

  if (p.metadata === null || typeof p.metadata !== 'object') bad('predicate.metadata is missing');
  else if (!(p.metadata.reproducible === null || typeof p.metadata.reproducible === 'boolean')) {
    bad('predicate.metadata.reproducible must be true, false, or null for "not observed"');
  }

  return problems;
}

/** The commit sha the statement claims, or null when it does not carry one. */
export function recordedCommitSha(st) {
  const v = st?.predicate?.invocation?.configSource?.digest?.sha1;
  return typeof v === 'string' ? v : null;
}

/** The toolchain digest the statement claims, or null. */
export function recordedToolchainDigest(st) {
  const m = (st?.predicate?.materials ?? []).find((x) => x?.uri === TOOLCHAIN_MATERIAL_URI);
  const v = m?.digest?.sha256;
  return typeof v === 'string' ? v : null;
}

/** `[{name, sha256}]` for every subject, in the order the statement lists them. */
export function subjects(st) {
  return (st?.subject ?? []).map((s) => ({ name: s?.name ?? null, sha256: s?.digest?.sha256 ?? null }));
}

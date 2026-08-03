// @vibeguard/external-adapters — multi-tool ensemble, v1.
//
// ★★ WHAT THIS PACKAGE IS AND, MORE IMPORTANTLY, WHAT IT IS NOT
//
// IS: a parser for security reports the USER already has, and a merger that says
// how much of the ensemble agreed about each weakness.
//
// IS NOT: a tool runner. There is no `spawn`, no `exec`, no `child_process`
// import anywhere under src/ — asserted by a test, not just claimed here.
// Neither Semgrep nor CodeQL is installed on the machine this was written on, so
// an invocation path would be code that has never once been executed shipping in
// a product, and Semgrep's telemetry would change VibeGuard's zero-egress audit
// surface from "read the source" to "read the source and reason about a
// subprocess's flags". types.ts argues both points at length. README.md states
// them for users.
//
// ★ THE EXPORT SURFACE IS DELIBERATELY NARROW AT ONE POINT: the internal
// `Candidate` shape of the merger and the `RuleDescriptor` shape of the SARIF
// parser are NOT exported. Both are working shapes that will change as the
// mapping grows, and exporting them would make an internal refactor a breaking
// change for the CLI. Everything a consumer needs to render a merge —
// `MergedFinding`, `EnsembleMember`, `ToolParticipation`, the agreement labels —
// is here.
//
// REGISTRATION AND CLI WIRING ARE NOT DONE HERE. The integrator owns
// apps/cli/**; this package ships the parsers, the merger and their tests.

export type {
  Agreement,
  AdapterOptions,
  EnsembleMember,
  EnsembleResult,
  EnsembleToolId,
  ExternalFinding,
  ExternalReport,
  ExternalToolId,
  MappingCoverage,
  MergedFinding,
  ProvenanceKind,
  RefusedResult,
  ToolParticipation,
  ToolProvenance,
  ToolSide,
} from './types.js';
export {
  AGREEMENT_ORDER,
  ENSEMBLE_TOOL_ORDER,
  ExternalReportError,
  notSupplied,
  suppliedReport,
  unreadableReport,
} from './types.js';

export type { WeaknessClass, WeaknessFamily } from './weakness-class.js';
export {
  WEAKNESS_FAMILIES,
  classifyCodeqlRuleId,
  classifyRuleId,
  classifySemgrepCheckId,
  classifyVibeguardRuleId,
  toolHasDetectorFor,
  weaknessFamily,
} from './weakness-class.js';

export { DEFAULT_LINE_TOLERANCE, isAbsolutePath, normalizePath, normalizeReportPath } from './location.js';

export { parseSemgrepReport } from './semgrep-adapter.js';
export { parseCodeqlSarifReport } from './codeql-adapter.js';

export type { EnsembleInput, VibeguardSide } from './result-merger.js';
export { mergeEnsemble, mergedConfidence, mergedSeverity } from './result-merger.js';

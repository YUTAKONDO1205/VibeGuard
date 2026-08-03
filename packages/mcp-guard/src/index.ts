// @vibeguard/mcp-guard — the generation-time guardrail (H5, §5.8; a PoC).
//
// WHAT THIS MOVES
//
// Every other VibeGuard channel runs after code exists: the CLI scans a tree,
// the Action scans a diff, the editor scans a file you already saved, the
// Chrome extension scans a completion you already read. All four are review. A
// review-time scanner has one structural weakness, and it is not detection
// quality — it is that somebody has to remember to run it, and the whole
// premise of the AI-generated-code problem is that the code arrives faster than
// anyone reviews it.
//
// This package is the same engine placed at the moment of creation instead: an
// MCP server an AI coding agent talks to, which adjudicates content on its way
// to disk and refuses the write when the content is critical or high. The
// product framing is an antivirus's resident real-time protection versus a
// scanner you remember to run — the detection is identical, the difference is
// entirely in when it is consulted.
//
// ★ WHAT THIS IS NOT, said first because a PoC that oversells is worse than one
// that does not exist. It is one tool, over one transport, with one interception
// path, and it does not enforce anything: it answers, and the agent may ignore
// the answer. `guard.ts` argues why that limitation is inherent to the design
// rather than a missing feature, and the README lists the rest.
//
// ★ THE BOUNDARY: this package must never be bundled into the Chrome or VS Code
// extensions. Not because it is heavy — it is small — but because it is a
// SERVER. The extensions ship into a browser and an editor, environments where
// a JSON-RPC responder that answers whatever speaks to it is a surface neither
// product has any reason to expose. The same argument as `analysis-graph`'s,
// reached from the opposite direction: that package is barred for its weight,
// this one for its shape. `MCP_GUARD_BUNDLE_SENTINEL` below is what makes the
// bar mechanical rather than a matter of discipline.

/**
 * A string that must never appear in a shipped browser or editor bundle.
 *
 * The same device as `AG_BUNDLE_SENTINEL` in `@vibeguard/analysis-graph`, and
 * deliberately the same SHAPE, so that `check-packaging-invariants.mjs` can
 * treat both with one mechanism instead of two.
 *
 * ★ IT IS A SECONDARY NEEDLE, and the measurement that established that is
 * recorded on `AG_BUNDLE_SENTINEL`: esbuild drops declarations nothing
 * references, so a `const` string no code reads can be tree-shaken out of a
 * module that WAS bundled — and it flattens re-exports, so a barrel like this
 * one may not be part of the bundle at all even when the package is. A leak
 * therefore need not leave this string behind. The primary needle is the
 * per-module path comment `packages/mcp-guard/`, which is emitted for every
 * module the bundler includes.
 *
 * That measurement is not repeated here, and this comment does not claim it
 * was: it was made against `analysis-graph` with the same bundler and the same
 * esbuild config, and the mechanism it describes is a property of the bundler
 * rather than of the package. If the extensions' build ever enables
 * minification, BOTH needles change character — the path comments disappear
 * entirely — and the viability gate in `check-packaging-invariants.mjs` is what
 * is supposed to notice.
 *
 * Never change this value casually: the checker hard-codes it, and a mismatch
 * makes the probe pass by searching for a string nobody emits, which is the
 * exact failure mode of a check that looks green forever.
 */
export const MCP_GUARD_BUNDLE_SENTINEL = 'vibeguard:mcp-guard:must-not-ship-in-extensions';

export { MCP_GUARD_VERSION } from './version.js';

export {
  adjudicate,
  renderVerdict,
  BLOCK_AT,
  type AdjudicateInput,
  type RefusalReason,
  type Verdict,
} from './guard.js';

export {
  createGuardServer,
  serve,
  PREFERRED_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  TOOL_NAME,
  type GuardServer,
  type GuardServerOptions,
  type LineSink,
  type LineSource,
} from './server.js';

// The NAME `ScanFn` is deliberately not re-exported. It is the seam that lets a
// caller substitute the scan, which exists so the fail-closed branch can be
// tested (see `guard.ts`) and for no other reason; naming it in the barrel
// would advertise "bring your own scanner" as a feature, and a guardrail whose
// scanner is a parameter is a guardrail whose guarantee is a parameter.
//
// This hides the name, not the capability — `GuardServerOptions.scan` is right
// there, and any consumer can satisfy it structurally. That is stated rather
// than glossed, because an omission mistaken for an enforcement is worse than
// no omission: the seam is a documentation decision, and the thing that
// actually keeps a wire client from reaching it is that `tools/call` has no
// path to `createGuardServer`'s options.

/**
 * Version reported as `serverInfo.version` at `initialize`.
 *
 * `0.1.0-poc0`, and NOT the repository's `0.3.3`, which is the deliberate part.
 * Every other version string in this repo answers "which release is this" and
 * they are checked against each other by `check-packaging-invariants.mjs` for
 * exactly that reason. This one answers a different question, asked by an MCP
 * client that has just connected: "how much should I trust what is on the other
 * end of this pipe?" Stamping the shipped tool version on a stretch-item proof
 * of concept would answer that question with the reputation of four released
 * channels, which this server has not earned and does not need — it is one tool
 * with one interception path, and the `-poc` suffix is the honest answer to a
 * client that reads it.
 *
 * Its own module, for the same reason `analysis-graph` gives: `server.ts` reads
 * it, and reading it from the package barrel — which re-exports `server.ts` —
 * is an ESM cycle that resolves but leaves the constant `undefined` at module
 * evaluation time, silently stamping every handshake with nothing.
 */
export const MCP_GUARD_VERSION = '0.1.0-poc0';

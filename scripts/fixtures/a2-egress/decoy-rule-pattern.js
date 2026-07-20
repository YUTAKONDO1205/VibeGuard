// DECOY — must produce ZERO hits.
//
// This mimics packages/rules/: a rule definition whose *data* mentions every
// network API by name so that it can detect them in user code. A grep-based
// egress check flags this file and, to get green again, would have to exclude
// the very bundle it is supposed to audit. The AST check must stay silent here,
// because nothing below is a call, a construction, or an import — it is all
// string and regex literals.
export const NETWORK_RULES = [
  { id: 'VG-NET-EXAMPLE-1', pattern: /fetch\s*\(/g, message: 'fetch() call' },
  { id: 'VG-NET-EXAMPLE-2', pattern: /new\s+XMLHttpRequest/g, message: 'XMLHttpRequest' },
  { id: 'VG-NET-EXAMPLE-3', pattern: /new\s+WebSocket/g, message: 'WebSocket' },
  { id: 'VG-NET-EXAMPLE-4', pattern: /navigator\.sendBeacon/g, message: 'sendBeacon' },
  { id: 'VG-NET-EXAMPLE-5', names: ["require('https')", "import 'node:net'", 'new Image().src'] },
];

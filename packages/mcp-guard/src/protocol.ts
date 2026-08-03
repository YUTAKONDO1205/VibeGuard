// JSON-RPC 2.0 over newline-delimited stdio — the wire half of MCP.
//
// ★ WHY THIS IS HAND-ROLLED RATHER THAN `@modelcontextprotocol/sdk`
//
// The SDK is the obvious choice and it was rejected on the same ground every
// other dependency in this repository is rejected: `@vibeguard/analyzer-core`
// and `@vibeguard/rules` have zero third-party dependencies, and that is not a
// stylistic preference — it is the property that lets the same engine run in a
// Chrome service worker, in VS Code, in the CLI and in the Action and provably
// agree. A guardrail that sits in front of the engine and drags a transitive
// dependency tree behind it would be the one component of the product a user
// cannot audit by reading it.
//
// The cost of hand-rolling is bounded and known, because the surface actually
// needed is three requests and one notification: `initialize`,
// `notifications/initialized`, `tools/list`, `tools/call` (plus `ping`, which
// real clients send as a liveness probe and which costs one line). Everything
// below is JSON-RPC 2.0 as specified, with the MCP-specific framing rule —
// one message per line, no embedded newlines — enforced by construction rather
// than by convention. What we do NOT get is the SDK's forward compatibility
// with protocol revisions; see `SUPPORTED_PROTOCOL_VERSIONS` in server.ts,
// where that gap is bounded rather than hidden.

/**
 * A JSON-RPC id as it may appear in a RESPONSE. `null` is legal here and only
 * here: it is what a peer must send back when the request was so malformed that
 * its id could not be recovered (JSON-RPC 2.0 §5). A request's own id is
 * `string | number` — `null` is not a valid request id — which is why the two
 * are separate types instead of one permissive alias.
 */
export type JsonRpcResponseId = string | number | null;

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: string | number;
  result: unknown;
}

export interface JsonRpcFailure {
  jsonrpc: '2.0';
  id: JsonRpcResponseId;
  error: JsonRpcError;
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

/** The JSON-RPC 2.0 reserved codes. Named so call sites read as intent. */
export const JSON_RPC = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const;

/**
 * What one line off the transport turned out to be.
 *
 * A discriminated union rather than "parse and throw", because the caller's
 * obligations differ per case in a way an exception cannot express: a blank
 * line gets NO reply, a notification gets NO reply, and a parse failure gets a
 * reply carrying `id: null`. Collapsing those into one throw is how a server
 * ends up answering a notification, which is a protocol violation that the
 * client is entitled to treat as fatal.
 */
export type Incoming =
  | { kind: 'blank' }
  | { kind: 'parse-error'; detail: string }
  | { kind: 'invalid'; id: JsonRpcResponseId; detail: string }
  | { kind: 'notification'; method: string; params: unknown }
  | { kind: 'request'; id: string | number; method: string; params: unknown };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Classify one transport line.
 *
 * ★ ARRAYS ARE REFUSED, and that is a decision rather than an omission.
 * JSON-RPC 2.0 defines batching, and MCP's 2025-06-18 revision removed it. A
 * server that half-supported it — accepting the array and answering only the
 * first element — would be worse than one that refuses, because the client
 * would wait forever for responses to elements 2..n. So the array shape gets an
 * explicit INVALID_REQUEST naming batching, which a client can act on, instead
 * of silence it cannot.
 *
 * `id: null` in a REQUEST is treated as a notification-shaped invalid message
 * rather than as a request with a null id: JSON-RPC reserves null for the
 * response side, and honouring it would mean emitting a response whose id
 * cannot be correlated with anything.
 */
export function parseIncoming(line: string): Incoming {
  if (line.trim() === '') return { kind: 'blank' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (err) {
    return { kind: 'parse-error', detail: err instanceof Error ? err.message : String(err) };
  }

  if (Array.isArray(parsed)) {
    return {
      kind: 'invalid',
      id: null,
      detail: 'batch requests (a JSON array) are not supported; send one message per line',
    };
  }
  if (!isPlainObject(parsed)) {
    return { kind: 'invalid', id: null, detail: 'a JSON-RPC message must be an object' };
  }

  // The id is read BEFORE the rest is validated, so that a message which is
  // malformed but correlatable still gets an answer the client can match to the
  // call it is blocking on. Reporting `id: null` for a message that plainly
  // carried an id would strand that call.
  const rawId = parsed['id'];
  const id: string | number | undefined =
    typeof rawId === 'string' || typeof rawId === 'number' ? rawId : undefined;

  if (parsed['jsonrpc'] !== '2.0') {
    return { kind: 'invalid', id: id ?? null, detail: 'missing or unsupported "jsonrpc" version' };
  }
  if (typeof parsed['method'] !== 'string' || parsed['method'] === '') {
    // A response (`result`/`error` instead of `method`) lands here too. This
    // server never issues requests, so anything shaped like a response to one
    // is a client bug and is reported as such rather than ignored.
    return { kind: 'invalid', id: id ?? null, detail: 'missing or non-string "method"' };
  }

  const method = parsed['method'];
  const params = parsed['params'];

  if (id === undefined) return { kind: 'notification', method, params };
  return { kind: 'request', id, method, params };
}

/**
 * Serialise one message to exactly one transport line.
 *
 * The MCP stdio framing rule is "messages MUST NOT contain embedded newlines",
 * and `JSON.stringify` satisfies it for free: a literal newline inside any
 * string is emitted as the two characters `\` `n`, and no other JSON production
 * can introduce one. So the framing is safe by construction and there is no
 * escaping pass to get wrong — which is the whole reason this is a two-line
 * function instead of a codec.
 *
 * The trailing `\n` is part of the frame, not cosmetic: without it the peer's
 * line reader holds the message in its buffer and the call appears to hang.
 */
export function encodeLine(message: JsonRpcResponse): string {
  return `${JSON.stringify(message)}\n`;
}

export function success(id: string | number, result: unknown): JsonRpcSuccess {
  return { jsonrpc: '2.0', id, result };
}

export function failure(
  id: JsonRpcResponseId,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcFailure {
  return data === undefined
    ? { jsonrpc: '2.0', id, error: { code, message } }
    : { jsonrpc: '2.0', id, error: { code, message, data } };
}

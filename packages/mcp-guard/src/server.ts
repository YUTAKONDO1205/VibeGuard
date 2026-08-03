// The MCP surface: `initialize`, `tools/list`, `tools/call`, `ping`.
//
// One tool, one interception path. The adjudication itself, and the argument
// for why this server does not write files, are in `guard.ts`.

import { adjudicate, renderVerdict, BLOCK_AT, type ScanFn, type Verdict } from './guard.js';
import {
  encodeLine,
  failure,
  parseIncoming,
  success,
  JSON_RPC,
  type JsonRpcResponse,
} from './protocol.js';
import { MCP_GUARD_VERSION } from './version.js';

/**
 * MCP protocol revisions this PoC was written against, newest first.
 *
 * ★ WHAT NEGOTIATION DOES AND DOES NOT PROMISE
 *
 * MCP negotiates a version at `initialize`: the client proposes one, and a
 * server that supports it echoes it back, or otherwise answers with a version
 * it does support and lets the client decide whether to continue. That is
 * implemented literally below.
 *
 * The honest limit, and the price of not taking the SDK dependency
 * (`protocol.ts` argues that trade): this list is a snapshot, and a revision
 * published after it was written will not appear here. The failure is graceful
 * — an unknown proposal gets `PREFERRED` back and the client disconnects or
 * downgrades, which is the specified behaviour — rather than a crash or, far
 * worse, a silent pretence of support. What this server implements is small
 * enough (three requests) that it has been compatible across all three of the
 * revisions listed; that is a reason the exposure is bounded, not a reason it
 * is zero.
 */
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'] as const;
export const PREFERRED_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

/**
 * ★ THE TOOL NAME, which is a user-interface decision and not a label.
 *
 * A model picks a tool by reading its name and description; the name is
 * therefore the load-bearing part of the interception, because a tool the model
 * does not think to call intercepts nothing.
 *
 * `guarded_write` was the working name and is REJECTED as a lie: nothing here
 * writes (see the header of guard.ts), and a name promising a write would leave
 * the agent believing the file had landed. That is the worst possible failure
 * for this package — the agent skips its real write, the file never exists, and
 * the guard is blamed for a bug it caused by naming.
 *
 * `scan_content` / `check_code` were rejected from the other side: they read as
 * optional analysis, the kind of tool an agent calls when it is unsure, and the
 * one thing this must not be is optional.
 *
 * `approve_write` keeps both halves. The VERB is what this server does —
 * approve or refuse — so the name cannot be misread as the bytes having landed.
 * The OBJECT is what the CALLER is about to do, which is what cues the model to
 * call it at the write boundary rather than whenever it feels uncertain. The
 * description then states the protocol in the imperative, because "may" in a
 * tool description is read by a model as "optional".
 */
export const TOOL_NAME = 'approve_write';

const TOOL_DESCRIPTION =
  'Adjudicate a file write BEFORE performing it. Call this with the full text you are ' +
  'about to write; it runs the VibeGuard security engine locally (no network) and answers ' +
  'ALLOWED or REFUSED. If the answer is REFUSED, do NOT write the file: the reply lists the ' +
  'rule id, line, and fix for every blocking finding — correct them and call this tool again. ' +
  `A write is refused when the content contains a finding at ${BLOCK_AT} severity or above. ` +
  'This tool does not touch the filesystem; after an ALLOWED answer, perform the write with ' +
  'your own file-writing tool.';

const TOOL_DEFINITION = {
  name: TOOL_NAME,
  description: TOOL_DESCRIPTION,
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        description:
          'The path you intend to write to. Used only to infer the language and to label ' +
          'the verdict — no file at this path is read, created, or modified.',
      },
      content: {
        type: 'string',
        description:
          'The COMPLETE text the file will have after your write, not a patch or a diff. ' +
          'A guard that is shown a fragment can only judge the fragment.',
      },
    },
    required: ['path', 'content'],
    additionalProperties: false,
  },
} as const;

/**
 * Sent to the client at `initialize` and, by most clients, into the model's
 * system context. This is the only place the interception can be made habitual
 * rather than incidental, so it states the loop rather than describing the tool.
 */
const INSTRUCTIONS =
  `VibeGuard generation-time guard. Before writing or overwriting any source file, call ` +
  `\`${TOOL_NAME}\` with the destination path and the complete intended contents. If it ` +
  `answers REFUSED, do not perform the write — fix the reported findings and call it again. ` +
  `The scan is local and nothing leaves this machine.`;

export interface GuardServerOptions {
  /**
   * Substitute scan. Present so `guard.ts`'s fail-closed branch is reachable
   * from a test; see the argument on `ScanFn`. Not a configuration surface —
   * there is no way to reach it from the wire.
   */
  scan?: ScanFn;
}

export interface GuardServer {
  /**
   * Handle one transport line. Returns the line to write back, or `undefined`
   * when the protocol requires silence (a blank line, or any notification).
   *
   * Synchronous, because everything it does is: the scan is a pure function and
   * this server has no I/O. That is not an implementation detail — it is what
   * makes the whole protocol surface testable by calling one function with a
   * string, which is how the tests below drive it.
   */
  handleLine(line: string): string | undefined;
}

function toolResult(verdict: Verdict): unknown {
  // ★ `isError` ON A REFUSAL, which is arguable and was argued.
  //
  // Read one way, a refusal is a SUCCESSFUL adjudication that happens to say
  // no, and `isError` should stay false. Read the other way, MCP's `isError` is
  // the flag that means "this call did not produce the effect you wanted — read
  // the text and react", and clients use it to route the result back into the
  // model's reasoning rather than filing it as a completed step.
  //
  // The second reading wins because of what the first one costs: a client
  // rendering a refusal as an ordinary success is a client whose agent
  // continues to the write. The failure of being too quiet here is exactly the
  // failure this package exists to prevent, and the failure of being too loud
  // is a retry.
  //
  // The cost is that a refusal and a scanner malfunction now share one flag. It
  // is paid in the TEXT, not in the flag: `renderVerdict` leads with
  // `REFUSED (<reason>)`, and `scan-failed` says in words that editing the
  // content is the wrong response.
  return {
    content: [{ type: 'text', text: renderVerdict(verdict) }],
    isError: verdict.decision === 'refuse',
  };
}

export function createGuardServer(options: GuardServerOptions = {}): GuardServer {
  const scan = options.scan;

  function handleRequest(id: string | number, method: string, params: unknown): JsonRpcResponse {
    switch (method) {
      case 'initialize': {
        const requested =
          typeof params === 'object' && params !== null
            ? (params as Record<string, unknown>)['protocolVersion']
            : undefined;
        const agreed =
          typeof requested === 'string' &&
          (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
            ? requested
            : PREFERRED_PROTOCOL_VERSION;
        return success(id, {
          protocolVersion: agreed,
          // Only `tools`. No `resources`, no `prompts`, no `logging` — every
          // capability declared is a surface a client may then drive, and this
          // server has exactly one thing to offer. Declaring capabilities it
          // does not implement is how a client ends up calling a method that
          // answers -32601 at the worst moment.
          capabilities: { tools: {} },
          serverInfo: { name: '@vibeguard/mcp-guard', version: MCP_GUARD_VERSION },
          instructions: INSTRUCTIONS,
        });
      }

      case 'ping':
        // The MCP liveness probe. An empty result is the whole contract; a
        // server that answered -32601 here would be killed by clients that
        // probe on a timer.
        return success(id, {});

      case 'tools/list':
        // No pagination cursor. There is one tool and there will be one tool —
        // the package's stated scope is a single interception path — so an
        // absent `nextCursor` is the correct terminal answer rather than an
        // unimplemented feature.
        return success(id, { tools: [TOOL_DEFINITION] });

      case 'tools/call': {
        if (typeof params !== 'object' || params === null || Array.isArray(params)) {
          return failure(id, JSON_RPC.INVALID_PARAMS, 'params must be an object');
        }
        const p = params as Record<string, unknown>;
        if (p['name'] !== TOOL_NAME) {
          // A wrong tool name is the CLIENT addressing a tool this server never
          // advertised, so it is a protocol error rather than a verdict. Unlike
          // a malformed `arguments` (which the model produced and can fix), no
          // amount of the model rereading a tool result changes which tool the
          // client dispatched.
          return failure(
            id,
            JSON_RPC.INVALID_PARAMS,
            `unknown tool ${JSON.stringify(p['name'])}; this server exposes only "${TOOL_NAME}"`,
          );
        }
        // Everything past this point is the model's input, so every remaining
        // way it can be wrong comes back as a REFUSAL the model will read —
        // including a missing `arguments` object. Fail-closed by construction:
        // there is no path from a malformed call to an allow.
        return success(id, toolResult(adjudicate(p['arguments'], scan)));
      }

      default:
        return failure(id, JSON_RPC.METHOD_NOT_FOUND, `unknown method "${method}"`);
    }
  }

  return {
    handleLine(line: string): string | undefined {
      const incoming = parseIncoming(line);

      switch (incoming.kind) {
        case 'blank':
          return undefined;

        case 'parse-error':
          // `id: null`, per JSON-RPC 2.0: the id could not be recovered from
          // text that is not JSON. The client cannot correlate this with a
          // pending call, which is precisely why it must still be SENT — a
          // silent drop leaves that call hanging until the client's timeout,
          // and the operator sees a hang instead of "your message was not
          // JSON".
          return encodeLine(
            failure(null, JSON_RPC.PARSE_ERROR, 'invalid JSON', incoming.detail),
          );

        case 'invalid':
          return encodeLine(
            failure(incoming.id, JSON_RPC.INVALID_REQUEST, 'invalid JSON-RPC request', incoming.detail),
          );

        case 'notification':
          // ★ NO RESPONSE. EVER. Not even an error.
          //
          // A notification has no id, so any response to it would carry a null
          // id the client cannot correlate — and JSON-RPC 2.0 forbids it
          // outright. This branch therefore swallows UNKNOWN notifications too
          // (`notifications/initialized` is the one that actually arrives, but
          // clients emit `notifications/cancelled` and others freely). The
          // tempting "reply -32601 so nothing is silently ignored" is the bug:
          // it puts an uncorrelatable message on the wire in the middle of a
          // session and strict clients close the connection.
          return undefined;

        case 'request':
          try {
            return encodeLine(handleRequest(incoming.id, incoming.method, incoming.params));
          } catch (err) {
            // The loop must survive anything a handler can do. A server that
            // dies on one bad message takes every in-flight call with it, and
            // the operator sees the agent hang rather than a named fault. Note
            // that the guard's OWN failures never reach here: `adjudicate`
            // catches the scan and turns it into a refusal, which is a verdict
            // rather than an exception. This is the backstop for the ways a
            // handler can fail that are not the scan.
            return encodeLine(
              failure(
                incoming.id,
                JSON_RPC.INTERNAL_ERROR,
                'internal error',
                err instanceof Error ? err.message : String(err),
              ),
            );
          }
      }
    },
  };
}

/**
 * Minimal readable/writable shapes, so `serve` can be handed `process.stdin` /
 * `process.stdout` in production and a pair of fakes in a test without either
 * side depending on `node:stream` types.
 */
export interface LineSource {
  /**
   * Narrowed to the literal `'utf8'` rather than `string`, which is not
   * pedantry: Node types this as `setEncoding(encoding?: BufferEncoding)`, and
   * a `string` parameter is assignable to that in NEITHER direction (the
   * optional `undefined` blocks one way, the `BufferEncoding` union the other),
   * so a `string` here makes `process.stdin` fail to satisfy this interface.
   * `'utf8'` is also the only value `serve` ever passes.
   */
  setEncoding(encoding: 'utf8'): unknown;
  on(event: 'data', listener: (chunk: string) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
}

export interface LineSink {
  write(chunk: string): unknown;
}

/**
 * Run the server over a byte stream.
 *
 * ★ NOTHING BUT JSON-RPC MAY REACH `output`.
 *
 * On stdio transport, stdout IS the wire. One stray `console.log` — a debug
 * print, a deprecation warning a dependency emits, a banner — lands in the
 * middle of the frame and the client's parser desynchronises for the rest of
 * the session. That is the single most common way a stdio MCP server is broken,
 * it fails far from its cause, and it is why this package has no logging at all
 * rather than logging that is careful. Diagnostics, if ever added, go to stderr.
 *
 * The line splitting is done here rather than with `node:readline` so that
 * `serve` depends on no Node module at all: the buffering is six lines, and the
 * alternative would drag a module import into the one file that is hardest to
 * unit-test. `\r` is stripped so a client on Windows that emits CRLF frames is
 * not answered with a parse error for every message.
 */
export function serve(input: LineSource, output: LineSink, options: GuardServerOptions = {}): void {
  const server = createGuardServer(options);
  let buffer = '';

  input.setEncoding('utf8');
  input.on('data', (chunk: string) => {
    buffer += chunk;
    let newline = buffer.indexOf('\n');
    while (newline !== -1) {
      const line = buffer.slice(0, newline).replace(/\r$/, '');
      buffer = buffer.slice(newline + 1);
      const reply = server.handleLine(line);
      if (reply !== undefined) output.write(reply);
      newline = buffer.indexOf('\n');
    }
  });
  input.on('end', () => {
    // A final message with no trailing newline is still a message. Clients
    // normally terminate frames properly, but dropping the tail on EOF would
    // lose exactly one call — the last one — which is the hardest kind of bug
    // to reproduce.
    const tail = buffer.replace(/\r$/, '');
    buffer = '';
    if (tail.trim() !== '') {
      const reply = server.handleLine(tail);
      if (reply !== undefined) output.write(reply);
    }
  });
}

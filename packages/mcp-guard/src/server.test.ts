// The server is driven through its ACTUAL JSON-RPC surface: every assertion
// below builds a request object, hands it to `handleLine` as a string, and
// reads the response object back off the wire format. Nothing calls
// `adjudicate` directly.
//
// That is a deliberate cost. Testing the guard function would be shorter and
// would prove less: the interesting failures of an MCP server are not in the
// verdict, they are in the framing — answering a notification, dropping a
// response id, dying on a malformed line — and none of those are reachable from
// a test that skips the protocol.
//
// ── ON SUPPRESSION PRAGMAS IN THIS FILE ───────────────────────────────────
//
// The fixtures below contain a real AWS access key ID pattern, because a
// blocking test whose payload does not actually match the rule is a test that
// cannot fail. The repository self-scan (`.github/workflows/security-scan.yml`)
// scans `packages/` and would report it, so it is suppressed — but with
// `disable-line` naming the rule, NOT the `disable-file` header used elsewhere
// for fixture files. Two reasons, in order:
//
//  1. `check-packaging-invariants.mjs` counts FILES carrying a `disable-file`
//     pragma against a fixed baseline, precisely so that adding one is a
//     decision somebody reviews. A line-scoped pragma is the smaller blast
//     radius and needs no baseline moved to admit it.
//  2. `disable-file` would silence VG-SEC-001 for the whole file, including the
//     falsifiability control below, which asserts that a LOWERCASED key is
//     allowed. If the rule were suppressed file-wide, that control would pass
//     for the wrong reason and the pair would stop being evidence of anything.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { MAX_FILE_BYTES } from '@vibeguard/analyzer-core';
import type { ScanResponse } from '@vibeguard/findings-schema';
import {
  createGuardServer,
  serve,
  PREFERRED_PROTOCOL_VERSION,
  TOOL_NAME,
  type GuardServer,
  type GuardServerOptions,
  type LineSink,
} from './server.js';

// ── Fixtures ───────────────────────────────────────────────────────────────
//
// Each was run through `scan()` before being written down, and the finding ids
// asserted below are the ids that run produced. Writing a plausible payload and
// asserting the finding you expect is how a test ends up green against a rule
// that never fired.

const CLEAN_JS = 'export function add(a, b) {\n  return a + b;\n}\n';

// Observed: exactly one finding, VG-SEC-001, severity `critical`, at line 2.
const AWS_KEY_JS =
  'export const client = createClient({\n' +
  '  accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n' + // vibeguard:disable-line VG-SEC-001
  '});\n';

// The falsifiability control. VG-SEC-001 is `/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g`
// — uppercase, no `i` flag — so this differs from the payload above ONLY in
// case and produces NO finding. Its job is to fail if the "refused" assertion
// ever starts passing for a reason other than the rule matching.
const AWS_KEY_LOWERCASED_JS =
  'export const client = createClient({\n' +
  '  accessKeyId: "akiaiosfodnn7example",\n' +
  '});\n';

// Observed: exactly one finding, VG-QUAL-001, severity `medium`, at line 4.
const EMPTY_CATCH_JS =
  'export function load(raw) {\n' +
  '  try {\n' +
  '    return JSON.parse(raw);\n' +
  '  } catch (e) {}\n' + // vibeguard:disable-line VG-QUAL-001
  '  return null;\n' +
  '}\n';

// ── Wire helpers ───────────────────────────────────────────────────────────

let nextId = 1;

/** Send one message; return the parsed response, or `undefined` if silent. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function send(server: GuardServer, message: Record<string, unknown>): any {
  const line = server.handleLine(JSON.stringify(message));
  if (line === undefined) return undefined;
  // The frame contract, asserted on every single exchange rather than once:
  // exactly one trailing newline and no embedded ones. A server that emits a
  // pretty-printed message is a server whose client desynchronises on message
  // two, and that is a bug no verdict assertion would ever catch.
  expect(line.endsWith('\n')).toBe(true);
  expect(line.slice(0, -1)).not.toContain('\n');
  return JSON.parse(line);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function callTool(server: GuardServer, args: unknown): any {
  const id = nextId++;
  const response = send(server, {
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: TOOL_NAME, arguments: args },
  });
  expect(response.id).toBe(id);
  return response;
}

/** The single text block of a `tools/call` result. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function textOf(response: any): string {
  expect(response.error).toBeUndefined();
  expect(response.result.content).toHaveLength(1);
  expect(response.result.content[0].type).toBe('text');
  return response.result.content[0].text as string;
}

function newServer(options?: GuardServerOptions): GuardServer {
  return createGuardServer(options);
}

// ── Handshake ──────────────────────────────────────────────────────────────

describe('MCP handshake', () => {
  it('answers initialize with the client protocol version when it is supported', () => {
    const r = send(newServer(), {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'x', version: '1' } },
    });
    expect(r.result.protocolVersion).toBe('2024-11-05');
    expect(r.result.capabilities).toEqual({ tools: {} });
    expect(r.result.serverInfo.name).toBe('@vibeguard/mcp-guard');
    // The instructions are the only place the interception can be made habitual
    // rather than incidental, so their presence is part of the contract.
    expect(r.result.instructions).toContain(TOOL_NAME);
  });

  it('falls back to its preferred version when the client proposes an unknown one', () => {
    const r = send(newServer(), {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '1999-01-01' },
    });
    expect(r.result.protocolVersion).toBe(PREFERRED_PROTOCOL_VERSION);
  });

  it('says NOTHING in response to a notification', () => {
    const server = newServer();
    expect(server.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }))).toBeUndefined();
    // Including notifications it does not know. Answering an unknown one with
    // -32601 would put an uncorrelatable id on the wire mid-session.
    expect(server.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: {} }))).toBeUndefined();
  });

  it('answers ping, which clients send on a timer', () => {
    const r = send(newServer(), { jsonrpc: '2.0', id: 7, method: 'ping' });
    expect(r).toEqual({ jsonrpc: '2.0', id: 7, result: {} });
  });

  it('advertises exactly one tool, with both arguments required', () => {
    const r = send(newServer(), { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    expect(r.result.tools).toHaveLength(1);
    const tool = r.result.tools[0];
    expect(tool.name).toBe(TOOL_NAME);
    expect(tool.inputSchema.required).toEqual(['path', 'content']);
    // The description carries the imperative ("do NOT write"), which is the
    // only lever this server has over an agent's behaviour.
    expect(tool.description).toContain('REFUSED');
  });
});

// ── The interception ───────────────────────────────────────────────────────

describe('approve_write', () => {
  it('ALLOWS a clean file', () => {
    const r = callTool(newServer(), { path: 'src/math.js', content: CLEAN_JS });
    expect(r.result.isError).toBe(false);
    const text = textOf(r);
    expect(text.startsWith('ALLOWED')).toBe(true);
    expect(text).toContain('no findings');
  });

  it('REFUSES a hard-coded AWS key and returns the finding', () => {
    const r = callTool(newServer(), { path: 'src/aws-client.js', content: AWS_KEY_JS });
    expect(r.result.isError).toBe(true);
    const text = textOf(r);
    expect(text.startsWith('REFUSED (findings)')).toBe(true);
    // The finding id is asserted literally. This is the observed id from a real
    // scan of this exact payload, not the id the rule is expected to have.
    expect(text).toContain('VG-SEC-001');
    expect(text).toContain('[critical/high]');
    expect(text).toContain('Blocking findings:');
    // And the agent is told what to do next, which is the only reason to return
    // findings at all.
    expect(text).toContain('call this tool again');
  });

  it('★ falsifiability control: the same payload lowercased is ALLOWED', () => {
    // VG-SEC-001 has no `i` flag. If this ever starts refusing, the assertion
    // above stopped depending on the rule and became a tautology.
    const r = callTool(newServer(), {
      path: 'src/aws-client.js',
      content: AWS_KEY_LOWERCASED_JS,
    });
    expect(r.result.isError).toBe(false);
    expect(textOf(r).startsWith('ALLOWED')).toBe(true);
  });

  it('does NOT block on a medium finding, but does report it', () => {
    // The threshold is `high` and above, matching the CLI's default
    // `--fail-on high` — so the guard refuses exactly what CI already refuses
    // to merge, and nothing more. See BLOCK_AT in guard.ts for why medium is
    // deliberately outside the blocking band.
    const r = callTool(newServer(), { path: 'src/loader.js', content: EMPTY_CATCH_JS });
    expect(r.result.isError).toBe(false);
    const text = textOf(r);
    expect(text.startsWith('ALLOWED')).toBe(true);
    expect(text).toContain('VG-QUAL-001');
    expect(text).toContain('Not blocking (below high)');
    expect(text).not.toContain('Blocking findings:');
  });

  it('REFUSES when the scan throws — fails CLOSED, and says the content is not the problem', () => {
    // The one branch no input can reach, so it is reached by substitution. See
    // the `ScanFn` comment in guard.ts for why the seam exists at all.
    const server = newServer({
      scan: (): ScanResponse => {
        throw new Error('simulated engine failure');
      },
    });
    const r = callTool(server, { path: 'src/math.js', content: CLEAN_JS });
    expect(r.result.isError).toBe(true);
    const text = textOf(r);
    // Content that a WORKING scan allows (asserted above) must be refused when
    // the scan is broken. That comparison is the whole claim.
    expect(text.startsWith('REFUSED (scan-failed)')).toBe(true);
    expect(text).not.toContain('REFUSED (findings)');
    expect(text).toContain('fails CLOSED');
    expect(text).toContain('simulated engine failure');
    // And it must not tell the agent to edit correct code, which would loop.
    expect(text).toContain('Do not edit the content in response to this');
  });

  it('REFUSES content over MAX_FILE_BYTES rather than skipping it', () => {
    const r = callTool(newServer(), {
      path: 'src/generated.js',
      content: 'a'.repeat(MAX_FILE_BYTES + 1),
    });
    expect(r.result.isError).toBe(true);
    expect(textOf(r).startsWith('REFUSED (too-large)')).toBe(true);
  });

  it('REFUSES a call with missing or non-string arguments', () => {
    const server = newServer();
    for (const args of [undefined, {}, { path: 'a.js' }, { content: 'x' }, { path: 'a.js', content: 42 }]) {
      const r = callTool(server, args);
      expect(r.result.isError).toBe(true);
      expect(textOf(r).startsWith('REFUSED (invalid-arguments)')).toBe(true);
    }
  });

  it('rejects an unknown tool name at the protocol level', () => {
    const r = send(newServer(), {
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: 'a.js', content: CLEAN_JS } },
    });
    expect(r.error.code).toBe(-32602);
    expect(r.error.message).toContain('unknown tool');
  });
});

// ── Malformed input ────────────────────────────────────────────────────────

describe('malformed input', () => {
  it('answers a parse error with id null AND keeps serving', () => {
    const server = newServer();
    const line = server.handleLine('{"jsonrpc": "2.0", "id": 1, "method":');
    expect(line).toBeDefined();
    const r = JSON.parse(line as string);
    expect(r).toMatchObject({ jsonrpc: '2.0', id: null, error: { code: -32700 } });

    // Survival is the assertion that matters. A guard that dies on one bad
    // line takes every in-flight call with it, and the operator sees a hang
    // rather than a fault.
    const after = callTool(server, { path: 'src/math.js', content: CLEAN_JS });
    expect(textOf(after).startsWith('ALLOWED')).toBe(true);
  });

  it('reports an invalid request against its own id when one can be recovered', () => {
    const r = send(newServer(), { jsonrpc: '1.0', id: 5, method: 'ping' });
    expect(r).toMatchObject({ id: 5, error: { code: -32600 } });
  });

  it('refuses a JSON-RPC batch explicitly instead of half-answering it', () => {
    const server = newServer();
    const line = server.handleLine(JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'ping' }]));
    const r = JSON.parse(line as string);
    expect(r).toMatchObject({ id: null, error: { code: -32600 } });
    expect(r.error.data).toContain('batch');
  });

  it('answers -32601 for an unknown method that carries an id', () => {
    const r = send(newServer(), { jsonrpc: '2.0', id: 3, method: 'resources/list' });
    expect(r).toMatchObject({ id: 3, error: { code: -32601 } });
  });

  it('stays silent on a blank line', () => {
    expect(newServer().handleLine('')).toBeUndefined();
    expect(newServer().handleLine('   ')).toBeUndefined();
  });
});

// ── The transport loop ─────────────────────────────────────────────────────

/** A `LineSource` a test can push bytes into. */
class FakeInput {
  private readonly listeners = new Map<string, Array<(chunk: string) => void>>();

  setEncoding(_encoding: string): this {
    return this;
  }

  on(event: string, listener: (chunk: string) => void): this {
    const bucket = this.listeners.get(event);
    if (bucket) bucket.push(listener);
    else this.listeners.set(event, [listener]);
    return this;
  }

  push(chunk: string): void {
    for (const l of this.listeners.get('data') ?? []) l(chunk);
  }

  end(): void {
    for (const l of this.listeners.get('end') ?? []) l('');
  }
}

class FakeOutput implements LineSink {
  readonly lines: string[] = [];
  write(chunk: string): void {
    this.lines.push(chunk);
  }
}

describe('stdio framing', () => {
  it('splits several messages out of one chunk, and tolerates CRLF', () => {
    const input = new FakeInput();
    const output = new FakeOutput();
    serve(input, output);

    input.push(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) +
        '\r\n' +
        JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) +
        '\n' +
        JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) +
        '\n',
    );

    // Two responses, not three: the notification is answered with silence.
    expect(output.lines).toHaveLength(2);
    expect(JSON.parse(output.lines[0] as string).id).toBe(1);
    expect(JSON.parse(output.lines[1] as string).result.tools).toHaveLength(1);
  });

  it('reassembles a message split across chunk boundaries', () => {
    const input = new FakeInput();
    const output = new FakeOutput();
    serve(input, output);

    const message = JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'ping' });
    input.push(message.slice(0, 10));
    expect(output.lines).toHaveLength(0);
    input.push(message.slice(10) + '\n');
    expect(JSON.parse(output.lines[0] as string).id).toBe(4);
  });

  it('answers a final message that arrives without a trailing newline', () => {
    const input = new FakeInput();
    const output = new FakeOutput();
    serve(input, output);

    input.push(JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'ping' }));
    expect(output.lines).toHaveLength(0);
    input.end();
    expect(JSON.parse(output.lines[0] as string).id).toBe(6);
  });
});

// ── Zero transmission ──────────────────────────────────────────────────────

describe('zero transmission', () => {
  it('has no network sink anywhere in its own sources', () => {
    // The product claim is that the scan is in-process and nothing leaves the
    // machine. `no-network-assert.yml` proves that for the SHIPPED closure by
    // AST-scanning built artefacts; this is the cheap, local, immediate version
    // of the same question, and it fails in this package's own suite rather
    // than in a workflow nobody runs locally.
    //
    // `.test.ts` files are excluded, and the reason is the same one that makes
    // `check-packaging-invariants.mjs` split its sentinel literal in half: this
    // file necessarily contains every token it searches for, so a probe that
    // read itself would report a leak that is not there — and the standard
    // response to a check that cries wolf is to delete the check.
    const NETWORK = /\bfetch\s*\(|node:https?|node:net|node:dgram|node:tls|XMLHttpRequest|WebSocket|\bhttps?:\/\//;

    const srcDir = dirname(fileURLToPath(import.meta.url));
    const sources = readdirSync(srcDir)
      .filter((name) => name.endsWith('.ts') && !name.endsWith('.test.ts'))
      .map((name) => [name, readFileSync(join(srcDir, name), 'utf8')] as const);

    // The floor that makes "found nothing" mean something. An empty scan must
    // not read as a passing scan — the failure this repository names in three
    // other places.
    expect(sources.length).toBeGreaterThanOrEqual(5);

    for (const [name, text] of sources) {
      expect(`${name}: ${NETWORK.test(text) ? 'NETWORK SINK PRESENT' : 'clean'}`).toBe(
        `${name}: clean`,
      );
    }
  });
});

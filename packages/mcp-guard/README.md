<!-- vibeguard:disable-file VG-SEC-001 -->
<!-- This file quotes a rule INPUT: the smoke check hands the guard an AWS-shaped
     key so that the refusal it documents actually happens. It previously wrote
     the key as "AKIA…", which made the documented pipeline print ALLOWED — the
     opposite of the output quoted above it. A README whose reproduction steps
     contradict its own screenshot teaches readers that the tool is broken. Same
     exemption, and the same reason, as CHANGELOG.md:1. -->

# @vibeguard/mcp-guard

A **stdio MCP server** that an AI coding agent talks to before it writes a file.
It runs the VibeGuard engine over the content in-process and answers `ALLOWED`
or `REFUSED`.

Every other VibeGuard channel is review-time — the CLI scans a tree, the Action
scans a diff, the editor scans a file you already saved. All of them share one
structural weakness that has nothing to do with detection quality: somebody has
to remember to run them. This package is the same engine placed at the moment of
creation instead. The framing is an antivirus's resident real-time protection
versus a scanner you remember to run; the detection is identical, the difference
is entirely in *when* it is consulted.

> **Status: proof of concept (H5, a stretch item).** One tool, one transport,
> one interception path. Read [Limitations](#limitations) before quoting this
> anywhere — several of them are structural, not backlog.

## The tool

| | |
|---|---|
| name | `approve_write` |
| input | `{ path: string, content: string }` |
| refuses | any finding at **`high`** severity or above |
| allows | everything else, and reports the below-threshold findings anyway |
| writes | **nothing, ever** |

`path` is used only to infer the language (`detectLanguageFromPath`) and to
label the verdict. No file at that path is opened, created, or modified.

A refusal returns the rule id, severity, line, masked evidence, and the
remediation text for every blocking finding, so the agent can fix and call
again. Real output, from the smoke check below:

```
REFUSED (findings) — src/aws.js
refused: 1 finding(s) at high or above.

Blocking findings:
  - VG-SEC-001 [critical/high] Hard-coded AWS access key ID
      src/aws.js:1
      at:  const k = "AKIA***";
      fix: Rotate the key, then load credentials from environment variables,
           AWS Secrets Manager, or your runtime IAM role.

The file was NOT written — nothing was written, because this tool never writes.
Fix the findings above and call this tool again with the corrected content.
```

The credential is masked in the evidence by the engine's own `maskSecret`, so a
guard that refuses a hard-coded key does not then hand that key back through a
second channel.

## Why it adjudicates instead of writing

This is the design question the package exists to answer, and the full argument
is in the header of [`src/guard.ts`](src/guard.ts). The short form:

1. **Writing buys no enforcement.** The client chooses which tool to call. Any
   agent that can call this server already has whatever filesystem or shell tool
   it was editing code with; making this a writer does not remove that one, it
   adds a second. Enforcement lives in the client's tool allowlist, one layer
   up, and no capability down here can manufacture it.
2. **It would widen the attack surface this product claims not to widen.** An
   MCP server that writes is an arbitrary-file-write primitive reachable by
   anything that can speak newline JSON-RPC to a pipe. Confining it means a root
   allowlist, symlink resolution, and a traversal policy — a configuration
   system guarding a capability the tool does not need.
3. **The scan is pure, which is why four channels agree.** `scan()` does no I/O
   anywhere; that is why the Chrome extension, which has no filesystem at all,
   runs the same engine as the CLI. Bolting a write onto the one caller that
   happens to have a disk would make this the only channel whose behaviour
   depends on one.

**The cost, stated plainly: this makes the guardrail advisory.** An agent that
ignores the refusal and writes anyway is not stopped by anything in this
package. That limitation is inherent to argument (1), not a missing feature.

## Behaviour that is not obvious

**The threshold is `high` and above, matching the CLI's default `--fail-on
high`.** So the guard refuses exactly what CI already refuses to merge, and
nothing more: it moves an existing verdict earlier in time rather than inventing
a stricter one only it enforces. `medium` is deliberately outside the blocking
band — it is where the low-confidence rules live, and a guard that blocks on
those puts the agent in a loop it cannot exit, after which a human removes the
guard from the client config. A guard that gets switched off protects nothing,
so its false-positive budget is a security parameter, not a UX one. Medium and
below are still **reported**; not blocking is not the same as not saying.

**It fails closed.** If the scan throws, the write is refused. An unguarded
agent writing insecure code is a known risk somebody is looking for; a *guarded*
agent writing insecure code is worse, because the guard's existence is why
nobody is looking. "Allowed because clean" and "allowed because the scanner
crashed" are the same two bytes on the wire, so the only safe direction is to
refuse. The refusal reason is `scan-failed`, distinct from `findings`, and says
in words that editing the content is the wrong response — otherwise the agent
would edit correct code, retry, crash again, and loop.

**Content over `MAX_FILE_BYTES` (1,000,000) is refused, not skipped.** The
constant is imported from `analyzer-core` rather than redefined, so "too big to
scan" means one thing across the product. The *response* deliberately differs
from `scanPath`'s, which skips: skipping here would mean unscanned content
landing under a green light.

**Zero transmission.** No network sink appears anywhere in this package's
sources, and a test in `server.test.ts` asserts it over the source files
directly. The scan is in-process.

## Running it

```sh
npm run build -w @vibeguard/mcp-guard
node packages/mcp-guard/dist/main.js      # speaks JSON-RPC on stdin/stdout
```

In an MCP client's server configuration:

```jsonc
{
  "mcpServers": {
    "vibeguard": {
      "command": "node",
      "args": ["/absolute/path/to/VibeGuard/packages/mcp-guard/dist/main.js"]
    }
  }
}
```

The handshake supports `2025-06-18`, `2025-03-26`, and `2024-11-05`; an unknown
proposal is answered with the newest supported version, per the spec, rather
than refused. Implemented methods: `initialize`, `notifications/initialized`,
`tools/list`, `tools/call`, `ping`.

Smoke-check it by hand — this is the exact pipeline whose output is quoted
above:

```sh
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"approve_write","arguments":{"path":"src/aws.js","content":"const k = \"AKIAIOSFODNN7EXAMPLE\";"}}}' \
 | node packages/mcp-guard/dist/main.js
```

**Nothing but JSON-RPC may reach stdout.** On stdio transport stdout *is* the
wire, and one stray `console.log` desynchronises the client's parser for the
rest of the session. That is why this package has no logging at all rather than
logging that is careful; the one startup line goes to stderr.

## Limitations

Ordered by how much they should change your reading of the above.

1. **Advisory, not enforcing.** See the argument for why. An agent may write
   without asking, or ignore the answer.
2. **It judges what it is shown.** The agent supplies the content. Nothing
   verifies that the bytes adjudicated are the bytes written, and nothing can
   at this layer — see (1). A guard shown a fragment can only judge the
   fragment, which is why the schema asks for the complete file text.
3. **A degraded scan still allows.** A `ScanDegradation` means the scan ran but
   did not read everything (a rule hit `REGEX_INPUT_CAP` at 50,000 characters,
   the scan-wide deadline, or the per-file match ceiling). Strict fail-closed
   reasoning says refuse; it allows, because refusing would make every file past
   50 KB permanently unwritable with no edit that fixes it, and a guard that
   gets switched off protects nothing. The degradation is rendered on the allow
   line so a partial scan is visible rather than silent. **This is the known
   fail-open seam in the design**, and it is a weaker position than the
   fail-closed rule above.
4. **Single-file analysis only.** The cross-file pass (`@vibeguard/analysis-graph`)
   is not wired in, so no design smell that needs a project index is reachable
   here — by construction, since the agent hands over one file's text.
5. **Protocol versions are a snapshot.** A revision published after this was
   written is not in the supported list. It degrades per spec rather than
   crashing; that bounds the exposure, it does not remove it.
6. **No path confinement, because there are no paths.** `path` is a label. This
   is a consequence of not writing, not a gap in a policy.

## The packaging boundary

**This package must never be bundled into the Chrome or VS Code extensions** —
not because it is heavy (it is small) but because it is a *server*. The
extensions ship into a browser and an editor, environments where a JSON-RPC
responder that answers whatever speaks to it is a surface neither product has
any reason to expose. Same conclusion as
[`@vibeguard/analysis-graph`](../analysis-graph/README.md)'s, reached from the
opposite direction: that package is barred for its weight, this one for its
shape.

`MCP_GUARD_BUNDLE_SENTINEL` in [`src/index.ts`](src/index.ts) is what makes the
bar mechanical rather than a matter of discipline; see the comment there for the
measured limits of the sentinel as a needle, and why the per-module path comment
`packages/mcp-guard/` is the primary one.

## Layout

```
src/
├── protocol.ts   JSON-RPC 2.0 over newline-delimited stdio (hand-rolled, zero deps)
├── guard.ts      adjudicate() — the threshold, the fail-closed path, the size cap
├── server.ts     initialize / tools/list / tools/call / ping, and the transport loop
├── main.ts       the executable entry point; the only file with a side effect
├── version.ts    MCP_GUARD_VERSION, reported as serverInfo.version
└── index.ts      public surface + MCP_GUARD_BUNDLE_SENTINEL
```

Zero third-party dependencies, including no MCP SDK — the handshake this needs
is three requests and one notification, and `analyzer-core`'s dependency-free
guarantee is the property that lets one engine run in four channels and provably
agree. [`src/protocol.ts`](src/protocol.ts) argues that trade and names what it
costs.

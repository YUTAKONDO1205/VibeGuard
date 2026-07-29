# samples/crossfile-safe — the zero-findings gate

## What must fire

**Nothing. Zero findings, from any rule, ever.**

This is the same service as `samples/crossfile-vulnerable/` — same three routers,
same five endpoints, same handlers, same data layer, identical observable
behaviour — refactored so that the authorization decision happens in exactly one
place: `middleware/require-role.ts`.

The project ships a "well-factored code produces zero findings" contract. A
design smell that fires here is a bug, not a near miss, and so is a finding from
any of the ordinary security rules. If a scan of this directory reports anything
at all, the correct response is to fix the rule, not to relax this fixture.

## Why VG-SMELL-010 must stay silent

The rule's four conditions (design addendum §7.2) fail here on **(b)** and
**(a)** together:

- Every privileged route names `requireRole(...)` in the middleware position of
  its registration, so the guard is reachable structurally from each route
  binding. That is the direct negation of condition (b), "the checks are written
  directly inside each handler, not in a middleware or guard".
- No controller body contains a role comparison at all, so condition (a),
  "similar checks exist in multiple files", has nothing to count. There is one
  comparison in the whole directory (`allowed.includes(user.role)` inside the
  guard) and it is in one file, in a function that is not a route handler.

Both failures are load-bearing. A rule that only checked (b) and let the
per-handler comparison count stand would still have to stay silent here, and a
rule that only counted comparisons would also stay silent here. The fixture does
not distinguish which mechanism the implementation uses — deliberately, since it
was written from the spec and not from any implementation.

## Why the ordinary rules must stay silent

Written to keep clear of every shipped single-file rule (47 when this fixture was
written, 71 today — the contract is "no finding from any rule", not from a fixed
list): no secrets or credential literals
(`process.env.PORT` is the only environment read), no `eval` or dynamic code, no
string-concatenated SQL — the data layer is in-memory array manipulation with no
query language anywhere, no disabled TLS verification, no wildcard CORS, no empty
catch blocks, no stub or passthrough function bodies, no placeholder emails, and
no debug flags. `requireRole` returns 401 before 403, so the unauthenticated case
is not silently treated as a role failure.

## How to verify

From the repo root:

```
npm run build
node apps/cli/dist/index.js samples/crossfile-safe --format json --fail-on never
```

`summary.total` must be `0`.

# @vibeguard/external-adapters

Multi-tool ensemble, v1. Parses security reports **the user already has** — Semgrep
`--json`, CodeQL SARIF 2.1.0 — normalises them onto VibeGuard's `Finding` shape, and
merges them with VibeGuard's own findings, labelling each merged row with how much of
the ensemble agreed about it.

Zero third-party dependencies. One workspace dependency (`@vibeguard/findings-schema`).

---

## Verification status — read this before quoting anything

**The adapters are verified against report FORMATS. Neither Semgrep nor CodeQL was
executed in this environment. Invocation is future work.**

That sentence is the honest summary; the detail matters, because the two adapters do
not rest on the same kind of evidence:

| | Semgrep adapter | CodeQL adapter |
|---|---|---|
| Fixture | `src/fixtures/semgrep-samples-vulnerable.json` | `src/fixtures/codeql-schema-derived.sarif` |
| Fixture provenance | **TOOL-RECORDED** — genuine bytes from a Semgrep 1.165.0 run over `samples/vulnerable`, trimmed from `paper_data/semgrep_vulnerable.json` (sha256 recorded in the fixture's own first key) | **SCHEMA-DERIVED, NOT TOOL-RECORDED** — hand-written against the OASIS SARIF 2.1.0 specification |
| Cross-checked against the shipped in-repo parser | Yes — `scripts/sec-transfer-semgrep.mjs`, agreement on `(check_id, path, line)` for all 20 recorded results | No such artifact exists; `scripts/sec-transfer-codeql.mjs` is itself scaffolded-and-blocked for the same reason |
| Rule-id → weakness mapping | Empirically derived (every pattern confirmed against a check_id Semgrep really emitted) | Correct-by-construction from the published `github/codeql` catalog, **unconfirmed** |

There is **no recorded CodeQL output anywhere in this repository** — checked `paper_data/`
and `security-experiment/_results/` — and the CodeQL CLI is not installed on the machine
this package was written on. Do not treat the two fixtures as equal evidence.

## Why this does not run the tools

No `spawn`, no `exec`, no `node:child_process`, anywhere under `src/`. Asserted by a
test (`weakness-class.test.ts`, *"the package cannot run a process or open a socket"*),
not merely promised. Two reasons:

1. **Neither tool is installed here.** An invocation path written under those conditions
   is code that has never once been executed shipping in a product — the argv it builds,
   the exit codes it tolerates, the stdout buffering it assumes, all unfalsified. This
   repository already refuses that class of claim: `scripts/sec-transfer-codeql.mjs`
   ships runnable and openly reports `blocked` rather than inventing numbers.
2. **It would change the zero-egress audit surface.** Semgrep phones home by default
   (`sec-transfer-semgrep.mjs` has to pass `--metrics=off` to stop it). "VibeGuard makes
   no network calls" is currently a property a reader can verify by reading this
   repository. Spawning a process that does make network calls turns it into "…except
   transitively, depending on flags". Parsing a file the user already has costs nothing
   on that axis.

The adapters are also pure with respect to the filesystem: they take report **text**, not
a path. The caller reads the file; `reportPath` is carried for provenance only and is
never opened here.

## Intended CLI shape (wired by the integrator, not here)

```
vibeguard scan . --ensemble \
  --semgrep-report semgrep.json \
  --codeql-report  codeql.sarif
```

`--ensemble` with no report is legal and produces a **degraded** run that says so:

```
ENSEMBLE DEGRADED — Semgrep was NOT run (no report supplied); CodeQL was NOT run
(no report supplied). Only VibeGuard participated. Absent tools reported nothing
because they were never asked, not because they found nothing: "no findings from
this tool" and "this tool was never run" are different facts, and only the first
is evidence. Nothing below may be read as corroborated or contradicted by an
absent tool.
```

With fewer than two participants the merger refuses to compute agreement at all —
every row is labelled `not-computable`. A one-tool run labelling everything "unique to
VibeGuard" would be a restatement of the input dressed as a comparison, and it would
look exactly like the output of a real three-tool run.

## Agreement labels

| label | meaning |
|---|---|
| `unanimous` | every participating tool with a mapped detector for this weakness class reported it (requires ≥2 such tools) |
| `corroborated` | ≥2 tools reported it, but at least one tool with a detector did not |
| `unique-to-tool` | exactly one tool reported it, **and** ≥1 other participating tool has a detector for the class and stayed silent — the row the research claim says needs investigation |
| `sole-detector` | only one participating tool has a detector for this class at all, so nobody else's silence carries information |
| `unclassified` | no weakness class could be derived, so the question cannot be asked |
| `not-computable` | fewer than two tools participated |

`sole-detector` and `unclassified` exist to stop two specific overstatements:

- Semgrep flags `math-random-used` in Go; VibeGuard has no rule for weak PRNGs in Go.
  Calling that *unique-to-Semgrep* invites "VibeGuard missed it", when VibeGuard never
  looks. That is a coverage gap, not a miss.
- Two unmapped findings on the same line might be the same weakness or might not. This
  package cannot tell, so it must not say.

**What no label can express:** a weakness *every* tool missed. It produces no row in any
report and therefore no row here. There is no bucket for it — an empty bucket would read
as a count of zero, i.e. this package asserting "nothing was missed" on no evidence.
`EnsembleResult.unobservable` states this in prose on every run.

## The weakness mapping is partial, and measurably so

Nine families, copied (not invented) from the `RULE_FAMILIES` tables of
`scripts/sec-transfer-semgrep.mjs` and `scripts/sec-transfer-codeql.mjs`. Measured on
the recorded Semgrep fixture — 20 results from a real run over `samples/vulnerable`:

```
classified 11   cookie-session-flags 2, injection-sql 2, weak-crypto 2, debug-enabled 1,
                eval-exec 1, injection-shell 1, insecure-transport 1,
                tls-verification-disabled 1
unmapped    9   no-csrf-exempt, express-check-csurf-middleware-usage,
                express-cookie-session-{default-name,no-domain,no-expires,no-path},
                express-session-hardcoded-secret, avoid_app_run_with_bad_host,
                math-random-used
```

45% unmapped on a corpus the Semgrep half of the table was *derived from*. Coverage on
arbitrary code will be worse, not better. `EnsembleResult.mappingCoverage` reports the
ratio and lists the unmapped rule ids on every run.

**Why not key agreement on CWE, which both tools emit?** Measured against the real bytes
and rejected. VibeGuard's `VG-AUTH-006` (missing `Secure`/`HttpOnly`) is CWE-614/1004;
Semgrep's `express-cookie-session-no-httponly` is CWE-522. Same weakness, same line of
the same file, no CWE-based join. CWE ids are carried on every finding
(`ExternalFinding.cweIds`) so a reader can see the divergence; they are not the join key.

## Four documented departures from the source tables

All in the tightening direction — a loosened mapping manufactures agreement, a tightened
one only loses coverage.

1. `/insecure-.*request` → `/insecure-[A-Za-z0-9_-]{0,40}request`
2. `/insecure-.*protocol` → `/insecure-[A-Za-z0-9_-]{0,40}protocol`

   Both are the ReDoS bound that governs product code here. They also stop the wildcard
   spanning rule-id path segments; blast radius stated in `weakness-class.ts`.

3. The `app-run-param-config` pattern of the `debug-enabled` family is **dropped**. It is
   a Semgrep rule-*file* name, and in this package's own recorded fixture it over-matches
   `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host`
   (CWE-668, host binding) — a different weakness from `debug-enabled` (CWE-489), on the
   same line of the same file. Harmless in the source script, which only asks whether a
   family fired in the same file; here it would manufacture cross-tool corroboration.
4. Every pattern is asserted quantifier-bounded by a test. The ReDoS census
   (`scripts/sec-a1-catalog.mjs`) reads only `packages/rules`, so nothing here is covered
   by it and the bound is the only protection.

## A divergence found in the existing repository

Both `scripts/sec-transfer-semgrep.mjs` and `scripts/sast-baseline-eval.mjs` already parse
Semgrep reports, and they normalise paths differently:

| input | `sec-transfer-semgrep.mjs` | `sast-baseline-eval.mjs` | |
|---|---|---|---|
| `samples\vulnerable\a.py` | `samples/vulnerable/a.py` | `samples/vulnerable/a.py` | agree |
| `./samples/a.py` | `samples/a.py` | `samples/a.py` | agree |
| `samples//a.py` | `samples/a.py` | `samples//a.py` | **differ** |
| `samples/x/../a.py` | `samples/a.py` | `samples/x/../a.py` | **differ** |
| `C:\repo\samples\a.py` (cwd `C:\repo`) | `samples/a.py` | `C:/repo/samples/a.py` | **differ** |

On the recorded artifacts both were written against — clean relative paths only — they
agree exactly, which is why nobody has been bitten. This package takes the sec-transfer
semantics for the unambiguous parts (collapse `.`, `..`, `//`, backslashes) and makes the
absolute-path reduction an explicit opt-in (`AdapterOptions.rootDir`), because a
user-supplied report may have been produced from any working directory. Recorded and
pinned in `parser-parity.test.ts`.

## Future work, named as such

- **Invocation.** Running the tools rather than ingesting their reports. Requires the
  tools to exist on a machine where the code can actually be exercised, and a decision
  about Semgrep telemetry that the zero-egress claim currently forecloses.
- **A tool-recorded CodeQL fixture.** Everything the CodeQL adapter asserts is about the
  SARIF format until one exists.
- **Extending the mapping.** `mappingCoverage.unmappedRuleIds` is the to-do list; each
  addition needs a source, the way every current entry has one.
- **Per-file coverage gating.** `ExternalReport.scannedPaths` is parsed and carried but
  not yet used to restrict agreement to files the other tool actually opened — the
  discipline `sast-baseline-eval.mjs` argues for at length.

## Tests

```
npx vitest run packages/external-adapters
npx tsc --noEmit -p packages/external-adapters/tsconfig.json
```

5 files, 112 tests. `parser-parity.test.ts` is the one that matters most: it runs this
package's Semgrep reading and a verbatim transcription of `sec-transfer-semgrep.mjs`'s
over the same recorded bytes, and additionally asserts that the transcribed lines still
exist character-for-character in that script — so an edit there breaks this build rather
than silently forking the answer to "what did Semgrep say".

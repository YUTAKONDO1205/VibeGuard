# smell-041-sanitize-after — VG-SMELL-041 POSITIVE (INVERTED, transformer)

**This directory also carries the index for the whole `smell-041-*` group.**

`search.ts` reads `req.query.term`, interpolates it into a SQL statement, runs
the statement, and *then* calls `escapeLike(term)`. The escaping is present and
correct and cannot have protected the query that already ran.

Expected: exactly one `VG-SMELL-041`, `severity: high` (a `query` sink hands the
value to an interpreter), `confidence: high` (INVERTED with a one-hop chain),
`scope: symbol`, primary location `search.ts:19`.

The handler is written INLINE at the route registration so the rule has to find
its body by containment — an anonymous arrow is named `<anonymous@17>`, and a
name-based lookup would search nothing and report nothing.

## The group

Nineteen directories. The rule is `VG-SMELL-041 — Temporal Security Coupling`,
and its claim is that a security operation the code **already contains** does not
apply to the value it was written for, because of order.

| directory | what it holds | expected |
| --- | --- | --- |
| `smell-041-sanitize-after/` | transformer after a query sink | **1 finding**, high/high |
| `smell-041-sanitize-bypassed/` | transformer first, raw value used at a file sink | **1 finding**, medium/medium |
| `smell-041-validate-after/` | validator after an exec sink, and a second sink it precedes | **1 finding**, high/high |
| `smell-041-mixed-placeholder/` | a statement that binds one value and interpolates another; a `??` that is not a placeholder | **2 findings**, high/high |
| `smell-041-combined-name/` | a callee carrying both vocabularies (`validateAndEscapeName`) | **1 finding**, medium/medium |
| `smell-041-sanitize-first/` | the transformed copy is what reaches the sink | silent |
| `smell-041-helper-guard/` | the same, through an imported helper namespace | silent |
| `smell-041-inline-at-sink/` | transformer applied inside a call sink's arguments | silent |
| `smell-041-inline-innerhtml/` | transformer applied inside an **assign-form** sink | silent |
| `smell-041-validate-first/` | validator before the use, and a validator inside the sink | silent |
| `smell-041-other-value/` | the sanitizer was written for a different value; and a direct dotted-source flow | silent |
| `smell-041-coercion/` | the transformer on the path is `Number(...)` | silent |
| `smell-041-no-sanitizer/` | a raw flow with no security operation at all | silent (`VG-INJ-*` owns it) |
| `smell-041-no-reach/` | source, sanitizer and sink present; no flow between them | silent |
| `smell-041-test-paths/` | the `sanitize-after` shape under `__tests__/` | silent |
| **★ `smell-041-exclusive-branches/`** | reduced from a MEASURED false positive: guard in the sibling branch | silent |
| **★ `smell-041-parameterized/`** | reduced from a MEASURED false positive: `$1` / `?` bound values, both orders | silent |
| **★ `smell-041-object-hop/`** | reduced from a MEASURED false positive: `options.a` at the sink, `options.b` at the guard | silent |
| **★ `smell-041-generic-words/`** | the vocabulary that let two of those three in | silent |

The four starred directories are not shapes imagined at a desk. The rule's first
version was run over the 1,000 repositories in `paper_data/corpus1k`; it produced
three findings and every one of them was wrong. Those three are the first three,
and the fourth is the vocabulary (`quote`, `strip`, `ensure`) that admitted two
of them.

## ★ Why every negative here is tested with a flow-count assertion first

H1 taint does **not** kill taint at a sanitizer call — `escapeLike(term)` is an
ordinary call to the dataflow pass — so a correctly sanitised handler still
produces a `TaintFlow` that reaches its sink. Silence therefore has to be earned
by the rule rather than inherited from an empty flow list, and every negative
above (except `no-reach/`, whose premise is inverted) asserts that H1 found a
flow **before** it asserts that the rule found nothing. Without that, each of
these directories would pass by being uninteresting.

## These contain deliberate injection

A flow that reaches a query sink has to be written as a real interpolated
statement, so the positives are genuine `VG-INJ-004` findings as well. The tests
call `temporalSecurityCoupling.analyze` directly rather than going through
`analyzeProject`, so nothing here depends on what the single-file rules do with
these files.

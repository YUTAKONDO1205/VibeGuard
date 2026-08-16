# compiler/driver — `vgcc` and `vg++`

A compiler driver that checks a build against `.vgpolicy.json`, runs clang-18,
and writes an evidence record saying what it checked. It is a wrapper, not a
compiler: the object files and executables it produces are the ones plain
clang-18 produces from the same command line, byte for byte, and that property
is measured rather than asserted (see [Non-invasiveness](#non-invasiveness)).

The contract it is written against is `compiler/schema/interfaces.md` and
`compiler/schema/policy.schema.json`. Neither is edited by this component.

```
node compiler/driver/cli/vgcc.mjs hello.c -O2 -o app
node compiler/driver/cli/vg++.mjs -c hello.cc -O2 -o hello.o
```

`cli/vgcc` and `cli/vg++` are `/bin/sh` shims for the same programs, so
`CC=…/cli/vgcc make` works without the caller knowing this is a node program.

They live in `cli/` and not in `bin/` because the repository's `.gitignore`
line 115 is `compiler/**/bin/`, written for the build directories CMake
components produce. It does not distinguish those from a `bin/` holding
sources, so entry points placed there are untracked, `git status` says nothing,
and the component is missing its executables in a fresh clone. Worth knowing
before another component here adds a `bin/`.

## What it does, in order

1. **Policy.** `.vgpolicy.json`, found by searching upward from the working
   directory, or named with `--policy <path>`. Validated against
   `policy.schema.json` before anything else happens. Unreadable, not JSON, or
   schema-invalid is **exit 4**, and no record is written — a record of a build
   checked against an unreadable policy is a record of nothing.
2. **Normalisation.** Response files expanded, `-Xclang` values paired,
   `-Wl,`/`-Xlinker` split, output and source files identified.
3. **Toolchain pin.** Every file the pin names is hashed and compared, the
   version clang reports is compared with the version the pin records, and
   `packages[].version` is compared with the version this machine reports for
   that package. A digest mismatch is `VG-CFG-001` and a package-version
   mismatch is `VG-CFG-013`; with `toolchain.requireDigestMatch` (default true)
   either is **exit 4** and the compiler is never run. A pinned version that
   could not be read back at all is `VG-CFG-014` and exit 3, not exit 4 —
   nothing disagreed, the check simply did not happen.
   Then the binary that will *actually be executed* — from `--vg-clang`, from
   `drivers.cc`/`drivers.cxx`, or from `PATH` — is reconciled with the pinned
   set, symlinks resolved on both sides. Running something the pin does not
   cover is `VG-CFG-012` and **exit 4**, and that one is *not* gated on
   `requireDigestMatch`: that switch downgrades "the pinned files are not the
   pinned bytes", and was never a decision to let the driver run a compiler the
   pin has never seen. `--vg-clang` is recorded as `VG-CFG-015` and confessed in
   `toolchain.compiler.overriddenByFlag`, which is inside the digested part of
   the record.
4. **Flags.** `flags.required` (`VG-CFG-004`), `flags.forbidden`
   (`VG-CFG-002`), `flags.optLevels` (`VG-CFG-003`).
4b. **Declared properties.** Every `policy.properties[]` entry is cross-checked
   against `compiler/schema/properties.json`: the id must be in the catalogue
   (`VG-CFG-016`), the kind must agree with it (`VG-CFG-017`), and there must be
   an implemented extractor at a checkpoint the policy asked for
   (`VG-CFG-018`). Any of those is **exit 3**, because `policy.schema.json`
   already writes that code down: "A property with no reachable checkpoint is
   exit 3, not a pass." An unreadable catalogue is `VG-CFG-019` and also exit 3.
   `properties: []` is legal and is recorded as `requested: 0` with a `claim`
   string saying in words that nothing was asked and therefore nothing was met;
   `properties` absent is a *different* recorded state (`configured: false`).
   Neither is ever rendered as "all requirements met".
5. **Plugin integrity.** `checkPlugins` from `plugin-integrity/integrity.mjs`,
   a static import. If that module is missing the driver refuses to start and
   exits 3 rather than running an unchecked build.
5b. **Security-preserving fallback**, and only when `policy.fallback` is
   present. See the section below. A policy that does not mention it never
   reaches this step and its record does not grow a `checks.fallback` key.
6. **Compile.** clang-18 / clang++-18, with the caller's argv. stdout and
   stderr are inherited, so diagnostics arrive unchanged and in order.
7. **Evidence.** Canonicalised and digested by `compiler/evidence/`. The driver
   does not carry its own canonicaliser.
8. **Exit code**, per the table below.

## Exit codes

`interfaces.md` §7 fixes the meanings. What this driver adds is the precedence
between them, first match wins:

| | Rule | Compiler run? |
|---|---|---|
| **4** | policy malformed, a pin digest does not match, or the compiler is not in the pinned set | no |
| **3** | the policy declares a property with no reachable checkpoint | no |
| **2** | findings at or above `failOn` | **no** — a forbidden configuration produces nothing to ship |
| **1** | clang failed; its diagnostics already reached the caller | yes, and it failed |
| **3** | the build succeeded but a check could not be completed, and `verification.failOnIncomplete` (default true) | yes |
| **3** | the record could not be written, so nothing was proved | yes |
| **0** | everything asked for was checked and nothing was found | yes |

Two of those orderings were wrong on the first attempt and are worth stating,
because both were only visible once the driver was run against a real
compiler:

- **2 outranks 3.** A named violation is more actionable than an unfinished
  check, both are non-zero, and the incompleteness is in the record either way.
  What must never happen is 3 collapsing to 0, and it cannot: the 0 branch is
  reached only when `complete` is true.
- **Except for the properties gate, which outranks 2.** That is the one
  departure, and it is deliberate: `policy.schema.json` fixes the code for that
  condition at 3, so letting a policy's own `failOn` re-map it to 2 would make
  the schema's own sentence false. It is also a different kind of statement —
  a finding says the build did something, this says a question the policy asked
  was never put to anything.
- **1 outranks 3, so the incompleteness test runs _after_ the build.** A source
  file that does not compile cannot have its pass pipeline captured, so the
  plugin check reports `complete: false` for every syntax error. Testing
  incompleteness first made every compile error exit 3 with the compiler never
  run and its diagnostics never printed — the driver answering "I could not
  check this" to a question whose real answer was "line 1 does not parse".

## Non-invasiveness

The research claim this component has to support is that a build observed
through the driver is the same build. Three rules keep it true, and all three
are measured:

- **The shipping build gets the caller's argv verbatim**, minus `--policy` and
  the `--vg-*` flags and nothing else. Not the normalised argv — the original,
  response files unexpanded, joined forms still joined. Normalisation decides
  what to *check*; if it also decided what to *compile*, a normalisation bug
  would become a miscompilation and the object file the driver blessed would
  not be the object file anyone else gets from the same command.
- **Anything the driver adds for its own benefit runs as a separate
  invocation**, with output redirected into the evidence work directory. Not
  the same run with an extra flag: `-mllvm -print-pipeline-passes` short-circuits
  codegen and writes a zero-byte object, so a driver that folded observation
  into the shipping build would be measuring a binary nobody ships and shipping
  a binary nobody measured.
- **Diagnostics are inherited, never buffered or re-printed.**

Measured on clang 18.1.3 (Ubuntu 1:18.1.3-1ubuntu1), node v18.19.1; the fixture
and full log are in `~/vg-lab/driver/`:

| | driver | plain clang-18 |
|---|---|---|
| `-c hello.c -O2 -o out.o` | `a3af2323…a8f94656` | `a3af2323…a8f94656` |
| `hello.c -O2 -o app` | `da308467…c752e6521` | `da308467…c752e6521` |
| `-c hello.c -O2 --vg-observe-pipeline` | `a3af2323…a8f94656` (1440 bytes) | — |

The third row is the positive control for the two-build rule: the driver is
told to add a flag that would truncate codegen, and the artefact the caller
keeps is still the plain one, at its normal size rather than zero. The negative
control for the comparison itself is `-O0` against `-O2`, which digests
differently — without it, "the digests matched" would also hold if the
comparison were a no-op.

## The toolchain pin

`toolchain.pin` in the policy points at this file, relative to the policy.
"Same version" is not the same bytes, so the pin records versions *and*
digests, and the digests decide.

```json
{
  "pinVersion": "toolchain-pin-v0",
  "clang": "18.1.3",
  "root": "/",
  "drivers": { "cc": "usr/bin/clang-18", "cxx": "usr/bin/clang++-18" },
  "packages": [
    { "name": "clang-18", "version": "1:18.1.3-1ubuntu1",
      "path": "usr/bin/clang-18", "sha256": "8ef402d4…" }
  ]
}
```

`path` is relative to `root` so a pin is portable between prefixes and so that
no absolute path has to be written into a record. Generate one from the
installed toolchain with:

```sh
node compiler/driver/tools/make-pin.mjs --out ~/vg-lab/driver/fixture/toolchain.pin.json
```

## Flag matching

A pattern matches a token when they are equal, when the pattern ends `=` and
the token starts with it (`-fsanitize=`), or when the pattern ends `*` and the
token starts with the rest (`-fstack-protector*`). Nothing else — in particular
a bare `-fstack-protector` does **not** match `-fstack-protector-strong`.
Substring matching fails in both directions at once (`-O2` matches inside
`-O2x`; `-fstack-protector` misses `-fstack-protector-strong`) and neither
failure is visible in a green build.

Patterns are matched against a space that includes the cc1 tokens behind
`-Xclang` and the linker tokens behind `-Wl,`/`-Xlinker`, so a policy that
forbids `-load` means it however the caller spelled it.

## Records

Written to `<evidence.out>/driver/driver-<first 16 hex of the digest>.json`.
Content-addressed, so the same build writes the same filename and two different
builds cannot land on one file and lose a record.

Everything a re-run cannot reproduce — wall clock, host, durations — lives in
`context`, which is excluded from the digest as a whole subtree. Two identical
builds therefore write one file, which is checked in the test suite.

That exclusion is a trap for anything a record needs to *commit* to. Which
compiler ran used to be recorded in `context`, so `resolvedFrom: "flag"` — the
record of a build that left the pin — was outside `evidenceDigest`, and a
pinned build and an overridden one digested identically. It now lives in
`toolchain.compiler`, and the pair of tests that keeps it there asserts both
directions: changing `overriddenByFlag` moves the digest, changing a `context`
field does not.

Absolute paths are gated twice: once by this component, naming the offending
JSON pointer, and again by `compiler/evidence/`'s own
`assertNoAbsolutePaths`. Either gate tripping means no file is written and the
run does not report clean.

## `policy.fallback` — the security-preserving fallback

`policy.schema.json` has carried a `fallback` block since the schema was
written, and nothing in `compiler/` read it. It now has one reader, here.
The intent, from the schema: recompile what lost a property at an approved lower
optimisation level, check again, and either offer the result as a candidate or
refuse the build.

**Off by default and opted into per policy.** A policy with no `fallback` block
never enters this step. This is not a research claim — `-fno-builtin-memset`,
`volatile`, and `memset_s` all exist — it is an operational feature.

### Where "lost" comes from

The driver does not decide `must-survive` for itself. The implemented extractors
for that kind are `ir.wipe-effect` and `ir.guarded-call`
(`compiler/schema/properties.json`), and both live in the C++ pass in
`compiler/llvm-pass/`, reachable only by loading a pass plugin into the
compilation — which the non-invasiveness rules above forbid folding into a
shipping build. A third JavaScript re-implementation of the counting rule inside
the driver would be a second definition of a measurement that already has one
home, the mistake `evidence-binding.mjs` refuses to make for canonicalisation.

So the verdict is **read, not derived**:

1. the driver emits textual IR for the invocation as the caller configured it,
   in a separate observation build the caller never sees;
2. it hands that IR to the observer named by `--vg-observer` and reads back the
   subset of `compiler/schema/observation.schema.json` it needs —
   `properties[].{id, kind, control, historyComplete, finalState}`;
3. if a declared `must-survive` property is not `PRESENT`, it recompiles at
   `fallback.profile` and asks **the same observer** again.

One observer for both readings is the point: a "before" from one oracle and an
"after" from another is not a comparison, and the difference between them would
be blamed on the recompile.

With `fallback.enabled: true` and no observer, the honest answer is not "nothing
was lost" — it is that the question was never put. That is `VG-CFG-022`,
`checks.fallback.status: "unsupported"`, and `complete: false`.

The observer contract, in full:

```
<observer> --profile <-O0|-O1|…> --unit <source> --ir <path to textual IR>
```

stdout is the record. A `.mjs`/`.cjs`/`.js` path is run with the node already
running; anything else is executed directly. A reading is refused, rather than
quoted, unless `historyComplete` is true **and** the entry's own `control` is
`PRESENT`: a measurement whose control did not survive has disowned itself.
`compiler/driver/test/observer-fixture.mjs` is a working one in 90 lines.

### Granularity is the translation unit, and the record says so

The schema's prose says "recompiling a function". A function is not something a
compiler driver can recompile: clang takes translation units and there is no
supported way to ask it for one function of one TU at another optimisation
level. Every record says `granularity: "translation-unit"`, and an invocation
with more than one source is **refused** (`multi-source-invocation`) rather than
rebuilt wholesale and described as the unit that lost the property.

### What it can and cannot do to an exit code

| outcome | `VG-CFG-020` | also | candidate |
|---|---|---|---|
| property `PRESENT` at the shipping level | — | — | — |
| lost, restored by the recompile | `high` | — | recorded, with digest and byte count |
| lost, still lost after the recompile | `critical` | `VG-CFG-021` at `critical`, or `high` with `rejectIfStillLost: false` | **none** |
| enabled and unable to run | — | `VG-CFG-022` at `high`, `complete: false` | — |

`critical` is the top of the severity ladder, so a still-lost property is at or
above every legal `failOn` and is exit 2 under all of them. **There is no
setting of `fallback` that turns a lost `must-survive` property into a pass**,
and `rejectIfStillLost: false` is not one either — it lowers `VG-CFG-021` by one
rung, recording that the policy chose not to treat the failed rescue as its own
separate refusal, and leaves `VG-CFG-020` where it is.

A policy that wants the candidate workflow sets `failOn: critical`, under which
the restored case (`high`) is exit 0 with the warning and the candidate both in
the record, and the still-lost case is still exit 2. The caller's own artefact is
always the one their command line asked for; the candidate is a separate file in
`<evidence.out>/work/driver-fallback/`, and the finding says so.

`fallback.profile` must appear in `flags.optLevels` when that list is
non-empty. Recompiling at a level the policy has never been evaluated at is the
complaint `VG-CFG-003` exists to make, and doing it as a *remedy* would make
that check meaningless.

## Driver-owned flags

Consumed by the driver, never forwarded to clang.

| Flag | |
|---|---|
| `--policy <path>` | use this policy instead of searching upward |
| `--vg-clang <path>` | run this compiler instead of the pinned or `PATH` one |
| `--vg-observer <path>` | the property observer `policy.fallback` needs. Ignored unless the policy enables fallback; on its own it changes nothing, which the test suite checks by digest |
| `--vg-observe-pipeline` | additionally run a separate observation build; the shipped artefact is unaffected |
| `--vg-verbose` | name the evidence record on stderr |
| `--vg-print-normalised` | dump the normalisation to stderr and carry on |

## Tests

This directory is outside the npm workspace globs, so the tests are `node:test`
and there are no dependencies:

```sh
node --test compiler/driver/test/*.test.mjs
```

Pass a glob, not the directory: on some Node builds here a bare directory
argument throws `MODULE_NOT_FOUND` before a single test runs.

184 tests, no skips on a machine with clang-18 and a POSIX shell. The live ones
skip with a printed reason elsewhere. One of them exists only to check that
they are running at all: `node:test` in Node 18 skips on `{ skip: null }` — the
check is for the property being *present*, not for it being truthy — and this
suite once reported green with all 26 live tests silently skipped.

`fallback-e2e.test.mjs` opens with a measurement rather than an assertion about
the driver: plain clang-18 on `guard.c` reports the `@vg_authorize` call site as
1 at `-O0`, 0 at `-O1` and 0 at `-O2`, with the `noinline` control at 1
throughout. The restored control and the reject control in that file differ only
in `fallback.profile`, so both rest on a difference that has been shown to
exist rather than on a mock that agrees with whatever it is asked.

## Checking policies without compiling

```sh
node compiler/driver/tools/check-gates.mjs <policy-or-directory>... [--allow-empty]
```

Runs the pin-reconciliation and property gates over every `.vgpolicy.json` it
finds, and prints `inputs=N checked=N skipped=S` as its last line. `inputs=0`
is a **failure** unless `--allow-empty` was passed: a scan pointed at the wrong
directory finds nothing, and a runner that reports that cheerfully has said a
tree is clean without opening it. A policy that cannot be read is a failure
too, not a skip; the only skips are the ones `VG_CHECK_GATES_SKIP` names, and
each of those is printed by name above the counting line.

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
3. **Toolchain pin.** Every file the pin names is hashed and compared, and the
   version clang reports is compared with the version the pin records. A
   mismatch is `VG-CFG-001`; with `toolchain.requireDigestMatch` (default true)
   it is **exit 4** and the compiler is never run.
4. **Flags.** `flags.required` (`VG-CFG-004`), `flags.forbidden`
   (`VG-CFG-002`), `flags.optLevels` (`VG-CFG-003`).
5. **Plugin integrity.** `checkPlugins` from `plugin-integrity/integrity.mjs`,
   a static import. If that module is missing the driver refuses to start and
   exits 3 rather than running an unchecked build.
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
| **4** | policy malformed, or a pin digest does not match | no |
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

Absolute paths are gated twice: once by this component, naming the offending
JSON pointer, and again by `compiler/evidence/`'s own
`assertNoAbsolutePaths`. Either gate tripping means no file is written and the
run does not report clean.

## Driver-owned flags

Consumed by the driver, never forwarded to clang.

| Flag | |
|---|---|
| `--policy <path>` | use this policy instead of searching upward |
| `--vg-clang <path>` | run this compiler instead of the pinned or `PATH` one |
| `--vg-observe-pipeline` | additionally run a separate observation build; the shipped artefact is unaffected |
| `--vg-verbose` | name the evidence record on stderr |
| `--vg-print-normalised` | dump the normalisation to stderr and carry on |

## Tests

This directory is outside the npm workspace globs, so the tests are `node:test`
and there are no dependencies:

```sh
node --test compiler/driver/test/
```

79 tests, no skips on a machine with clang-18. The live ones skip with a
printed reason elsewhere. One of them exists only to check that they are
running at all: `node:test` in Node 18 skips on `{ skip: null }` — the check is
for the property being *present*, not for it being truthy — and this suite once
reported green with all 26 live tests silently skipped.

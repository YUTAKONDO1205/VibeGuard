# artifact-integrity — is the protection actually in the binary?

Everything else in this repository reads source, or IR, or a diff. This reads
the finished ELF and asks one question per property: **is the effect in the
bytes?** Not "was the flag on the command line" — a flag can be overridden by a
later flag, dropped by a wrapper, silently ignored for the target, or ignored
because nothing in the program was eligible for it.

The dangerous failure for a checker like this is not missing a bad binary. It is
reporting a bad binary **clean**, because the marker it looked for was the wrong
one. Most of the design below exists because of a specific measurement where the
obvious marker gives the wrong answer.

## 1. Findings

| Id | Severity | What |
|---|---|---|
| `VG-ART-003` | high | A required hardening property is `ABSENT`: `pie`, `nx`, `relro-full`, `stack-protector`, `fortify`, `build-id` |
| `VG-ART-004` | critical | A section or a `PT_LOAD` segment is both writable and executable |
| `VG-ART-005` | critical | A literal from `policy.artifact.forbidStrings` survived into the image |
| `VG-ART-006` | medium | The image names a directory on the machine that built it, or ships debug information |
| `VG-ART-007` | high | A `DT_NEEDED` the policy does not authorise, or a `DT_RPATH`/`DT_RUNPATH` baked into the image |

`VG-ART-005` is not a free choice: `compiler/schema/policy.schema.json` already
pins `artifact.forbidStrings` to it. The rest are allocated around that fixed
point inside the `VG-ART-0NN` namespace reserved in
`compiler/schema/interfaces.md`.

**`VG-ART-001` — the artefact digest does not match its pin — is deliberately
not emitted here.** That belongs to the component that owns the pin;
`compiler/evidence/verify.mjs` already reports a bytes-vs-`artifact.sha256`
mismatch. This verifier computes the digest, reports it, and exits `4` on a
`--pin` mismatch **without** inventing a finding id for it.

`VG-ART-007` is newly allocated by this component and has not been ratified
anywhere else in the schema; the dependency check is off unless the policy sets
`allowedDynamicDependencies`.

## 2. Exit codes

`compiler/schema/interfaces.md` section 7: `0` clean · `1` tool failed ·
`2` findings · `3` **a check could not be completed** · `4` digest or policy.
**`3` is never `0`.**

## 3. The four states, and why two properties abstain

Properties are reported with the `interfaces.md` vocabulary — `PRESENT`,
`ABSENT`, `LOST`, `REINTRODUCED`, `NOT_APPLICABLE`, `NOT_OBSERVED` — and the
last two carry the weight.

For a **statically linked** image, `stack-protector` and `fortify` are
`NOT_OBSERVED`. Measured, on this toolchain:

| | `__stack_chk_fail` | `__*_chk` defined | canary loads | `_chk` call sites |
|---|---|---|---|---|
| `-static -fstack-protector-strong -D_FORTIFY_SOURCE=2` | **defined** | 9 | **355** | 206 |
| `-static -fno-stack-protector -U_FORTIFY_SOURCE` | **defined** | 8 | **353** | 204 |

The C library is itself built with both, so it brings them in regardless. The
symbol oracle returns the same answer for both binaries. The instruction oracle
returns 355 against 353, two instructions apart in a 124 000-instruction image.
Neither separates them at whole-image granularity, so the honest answer is that
the question was not observed — and the run exits `3`, not `0`.

A verifier that reported `PRESENT` here would call the unprotected static
binary hardened. That is the failure this component is built around.

## 4. The measured table

Full version, with the reproducer, in
`compiler/elf-verifier/artefact-ground-truth.md`. The rows that decide the shape
of the code:

| What was expected | What was measured | Consequence |
|---|---|---|
| `-Wl,-z,norelro` clears the eager-binding flags | `PT_GNU_RELRO` is gone, `DT_FLAGS=0x8` and `DT_FLAGS_1=0x8000001` **remain** | RELRO needs the segment **and** eager binding; the flags alone pass an unprotected binary |
| `-Wl,-z,relro,-z,lazy` keeps eager binding | `PT_GNU_RELRO` remains, `DT_FLAGS` **absent**, `DT_FLAGS_1=0x8000000` | the segment alone passes a partially protected binary |
| `-z now` sets `DT_BIND_NOW` | `DT_BIND_NOW` (tag 24) is **absent on all 23 fixtures** | a `DT_BIND_NOW`-only check reports partial RELRO for everything this linker builds |
| `ET_DYN` means PIE | a shared object is `ET_DYN` with **no `DT_FLAGS_1` at all** | PIE is `ET_DYN` **and** `DF_1_PIE`; for a shared object it is `NOT_APPLICABLE` |
| the disassembler names the fortify callee | GNU objdump prints `<__strcpy_chk@plt>`, llvm-objdump prints `<.plt.sec+0x20>` for the same bytes | the call-site oracle is the `R_X86_64_JUMP_SLOT` relocation, read from the bytes |

Twenty-three real binaries; the verdicts are asserted against this table by
`tools/verify-real-fixtures.mjs` (235 comparisons) and, with a second and
independently written reader, by `compiler/elf-verifier/artefact-controls.mjs`
(323 comparisons).

## 5. The oracle

`interfaces.md` section 4: count the effect, never the symbol name. At IR that
means `call void @llvm.memset` rather than a grep that also matches the
surviving `declare`. The artefact-level twin of that mistake is a name sitting
in `.dynstr` with nothing calling it, so the oracle here is the
**linker-materialised call site**: one `R_X86_64_JUMP_SLOT` relocation per
PLT-resolved callee, readable with no external tool at all.

The fixture `fortify-name-only` is exactly the failing case — `__strcpy_chk` and
`__stack_chk_fail` in `.dynstr`, no undefined symbol, no relocation — and the
verifier reports `ABSENT` for it. No compiler will produce that image for you,
which is why the test fixtures are synthesised.

Fortify carries a second half that a name search cannot have: the **fortifiable
surface**. Zero `_chk` call sites in a program that also makes no fortifiable
call is `NOT_OBSERVED`, not `ABSENT` — nothing was there to fortify.

## 6. Residue, and its control

`policy.artifact.forbidStrings` is searched over the raw bytes with
`Buffer.indexOf`, not against an extracted string list: a secret that straddles a
non-printable byte would be split by an extractor and the artefact reported
clean.

`properties.json` states the rule for this property class — *"a string that is
expected to be present, so that an extractor which has stopped finding anything
is distinguishable from an artefact that is clean"*. `--expect <s>` is that
control. **If a control string is not found, the residue scan is `INCOMPLETE`
and the forbidden-string count is reported as `null`, never as `0`.**

Build-path residue is matched by shape, not by a list of hostnames: per-user home
directories on four platforms, plus absolute paths under no distribution prefix.
The interpreter path `/lib64/ld-linux-x86-64.so.2` is in every dynamic
executable, so a detector that flags any absolute path flags every binary on the
system; that negative is a test. Reported paths are **redacted** — the shape
survives, the content does not.

The shapes are assembled from fragments at runtime and each carries a positive
control, because one of them once compiled cleanly, ran on every scan, and
matched nothing: inside a character class `\/` is an escaped forward slash, and
the backslash the Windows shape needed had vanished. `selfTestShapes()` and the
test that calls it are that bug's headstone.

## 7. The counting contract

Every runner here prints `inputs=N checked=C skipped=S` and **exits non-zero
when `N` is 0** unless `--allow-empty` was passed. The guard is in one place per
program, at the single exit point, and `test/cli.test.mjs` runs the binary
against an empty directory and asserts the code.

Skipping is not passing. A file that exists and cannot be read as ELF64 is
`INCOMPLETE`. A fixture the expectation table names and the directory does not
hold is a **failure**; `VG_ART_ALLOW_MISSING_FIXTURES=1` downgrades it to a skip
and then every skipped case is listed by name — and a run in which nothing was
actually read still exits `3`.

## 8. Running it

```sh
node bin/vg-artefact-verify.mjs --help

node bin/vg-artefact-verify.mjs ./build/app \
  --require pie,nx,relro-full,stack-protector,fortify,build-id,no-writable-executable-section,no-debug-path \
  --forbid 'AKIA' --expect 'my-release-banner' \
  --allowed-lib libc.so.6

node bin/vg-artefact-verify.mjs --policy policy.json --recursive ./dist --json record.json

npm test -w @vibeguard/artifact-integrity
```

The real-binary check needs a Linux toolchain:

```sh
bash compiler/elf-verifier/artefact-fixtures.sh /somewhere/matrix
node tools/verify-real-fixtures.mjs --dir /somewhere/matrix/bin --verbose
```

## 9. Boundary

This package imports **nothing** from `compiler/`. `packages/**` and
`compiler/**` do not reference each other in either direction and that is
currently measured at zero; the exit-code constants and the finding shape are
restated here rather than imported, and `test/boundary.test.mjs` fails if any
file ever grows such a reference. It has no dependencies and no build step, so
adding it to the `packages/*` workspace glob cannot break `npm run build`.

## 10. What is not covered

- **`-static-pie`** is classified but never measured against a real one.
- **Non-x86-64 / ELF32 / big-endian** return `supported: false` with a reason;
  callers must treat that as "could not look".
- **clang** was not used for the table; it is gcc 13.3.0 throughout.
- **A protector build with no eligible function** reads `ABSENT` — correct for
  the artefact, misleading about the flag. Stated in the finding's own note.
- **`.rela.plt` is x86-64.** Other architectures spell the call-site surface
  with different relocation types and are not handled.

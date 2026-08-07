# artefact verifier — the measured table

Everything the artefact hardening detector decides was written against this
table. The table was produced first, by building **one** fixture with each
hardening flag on and off and reading the resulting bytes; the detector came
second. That order is the point. Written the other way round, four of the rows
below would have been wrong, and two of them wrong in the direction that reports
an unprotected binary as clean.

Reproduce with:

```sh
bash compiler/elf-verifier/artefact-fixtures.sh <workdir>
node packages/artifact-integrity/tools/verify-real-fixtures.mjs --dir <workdir>/bin --verbose
```

Toolchain the table was taken from: **gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1)
13.3.0**, **GNU binutils 2.42**, **llvm-objdump 18.1.3**, x86-64 Linux. The
distribution's gcc already defaults to PIE, full RELRO, `noexecstack` and a
build id, so on this toolchain the *negative* fixtures are the ones that need
flags.

## 1. Structural fields, per fixture

Read out of the bytes with a struct decoder, not out of any tool's printed
lines. `STACK` is `PT_GNU_STACK.p_flags`; `RELRO` is whether `PT_GNU_RELRO`
exists; `SP` is whether `__stack_chk_fail` is an undefined import or a
`R_X86_64_JUMP_SLOT` target; `CHK` lists the `__*_chk` JUMP_SLOT targets;
`W+X` lists sections with `SHF_WRITE|SHF_EXECINSTR`.

| fixture | e_type | STACK | RELRO | INTERP | DT_FLAGS | DT_FLAGS_1 | BIND_NOW | SP | CHK | build-id | W+X | .debug_\* |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `sp-on` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | **yes** | – | yes | – | 0 |
| `sp-off` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `pie-on` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `pie-off` | **2** | 6 | yes | yes | **–** | **–** | absent | no | – | yes | – | 0 |
| `relro-full` | 3 | 6 | **yes** | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `relro-part` | 3 | 6 | **yes** | yes | **–** | **`0x8000000`** | absent | no | – | yes | – | 0 |
| `relro-none` | 3 | 6 | **no** | yes | **`0x8`** | **`0x8000001`** | absent | no | – | yes | – | 0 |
| `nx-on` | 3 | **6** | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `nx-off` | 3 | **7** | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `fortify-on` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | **`__strcpy_chk`** | yes | – | 0 |
| `fortify-off` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `buildid-on` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | **yes** | – | 0 |
| `buildid-off` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | **no** | – | 0 |
| `dbg-on` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | **6** |
| `dbg-off` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | no | – | yes | – | 0 |
| `rpath` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | yes | `__strcpy_chk` | yes | – | 0 |
| `hardened` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | yes | `__strcpy_chk` | yes | – | 0 |
| `hardened-stripped` | 3 | 6 | yes | yes | `0x8` | `0x8000001` | absent | yes | `__strcpy_chk` | yes | – | 0 |
| `unhardened` | **2** | **7** | **no** | yes | – | – | absent | no | – | **no** | – | **6** |
| `static-hardened` | 2 | 6 | yes | **no** | – | – | absent | n/a | n/a | yes | – | 0 |
| `static-plain` | 2 | 6 | yes | **no** | – | – | absent | n/a | n/a | yes | – | 0 |
| `libshared.so` | **3** | 6 | yes | **no** | **–** | **–** | absent | no | – | yes | – | 0 |
| `wx-on` | 3 | 6 | no | yes | `0x8` | `0x8000001` | absent | no | `__printf_chk` | yes | **`.vgwx`** | 0 |

## 2. The four rows that contradict the obvious implementation

### 2.1 `-Wl,-z,norelro` leaves eager binding set

`relro-none` has **`DT_FLAGS = 0x8` (`DF_BIND_NOW`) and `DT_FLAGS_1 = 0x8000001`
(`DF_1_NOW | DF_1_PIE`)** — byte for byte the same flag words as the fully
hardened link. Only `PT_GNU_RELRO` is gone. **A RELRO check keyed on eager
binding reports this binary as full RELRO.**

### 2.2 `-Wl,-z,relro,-z,lazy` leaves the segment in place

`relro-part` keeps `PT_GNU_RELRO` and drops eager binding entirely: no
`DT_FLAGS` tag at all, `DT_FLAGS_1 = 0x8000000` (PIE only). **A RELRO check
keyed on `PT_GNU_RELRO` reports this binary as full RELRO.**

So full RELRO needs both halves, and each half alone has a fixture that defeats
it. Both are asserted, in both directions, in `properties.test.mjs`.

### 2.3 `DT_BIND_NOW` is absent everywhere

On all 23 fixtures — including the fully hardened link, including
`-Wl,-z,now` — the historical `DT_BIND_NOW` tag (24) **is not emitted**. GNU ld
2.42 spells eager binding only through `DT_FLAGS`/`DT_FLAGS_1`. A checker that
looks only for `DT_BIND_NOW` reports *partial RELRO for every binary this
toolchain produces*, which is the false-positive form of the same mistake.

All three legal spellings are accepted; the record says which one fired.

### 2.4 `ET_DYN` alone is not PIE

`libshared.so` is `e_type = 3` and carries **no `DT_FLAGS_1` at all**. A PIE
check on `e_type` alone reports a shared library as a position-independent
executable. PIE is `ET_DYN` **and** `DF_1_PIE`; for a shared object the property
is `NOT_APPLICABLE`, not `PRESENT`.

## 3. The row that makes two properties abstain

`-static`, whole-image granularity:

| | `__stack_chk_fail` | `__*_chk` defined | canary loads (`%fs:0x28`) | `_chk` call sites |
|---|---|---|---|---|
| `static-hardened` (`-fstack-protector-strong -D_FORTIFY_SOURCE=2`) | **DEFINED** | 9 | **355** | 206 |
| `static-plain` (`-fno-stack-protector -U_FORTIFY_SOURCE`) | **DEFINED** | 8 | **353** | 204 |

The C library is itself built with the protector and with fortified wrappers, so
it brings both in regardless. The symbol oracle gives the same answer for both.
The instruction oracle gives 355 against 353 — a two-instruction difference
buried in a 124 000-instruction image.

**Neither oracle separates them at whole-image granularity.** Therefore a static
image is `NOT_OBSERVED` for `stack-protector` and `fortify` — never `PRESENT`,
never `ABSENT` — and the run exits 3, not 0. Deciding it needs per-object
attribution, which is a different observation point and a different component's.

This is the row that the brief's "dangerous failure" describes: a detector that
reported `PRESENT` here because it found the symbol would call `static-plain`
protected.

## 4. The oracle: count the call site, not the name

The two disassemblers installed here print the *same bytes* differently:

```
GNU objdump 2.42   call  1090 <__strcpy_chk@plt>
llvm-objdump 18.1  callq 0x1090 <.plt.sec+0x20>
```

A fortify detector written against the first spelling counts zero under the
second. So the call-site oracle used here is **structural**: the
`R_X86_64_JUMP_SLOT` relocation in `.rela.plt`. The linker materialises one
slot per PLT-resolved callee, and it is readable with no external tool at all.

Measured, and the negative direction matters as much as the positive:

| fixture | `.rela.plt` JUMP_SLOT | in `.dynstr` |
|---|---|---|
| `fortify-on` | `__strcpy_chk` | `__strcpy_chk` |
| `fortify-off` | – | – |
| `sp-on` | `__stack_chk_fail` | `__stack_chk_fail` |
| `sp-off` | – | – |

The name being present in `.dynstr` with nothing calling it is the artefact-level
twin of grepping IR for `llvm.memset` and matching the surviving `declare`. The
synthetic fixture `fortify-name-only` is exactly that image, and the verifier
reports `ABSENT` for it.

The canary-load instruction oracle agrees with the structural one on every
dynamic fixture, with a control that cannot be zero:

| fixture | canary loads | `.text` instructions (CONTROL) |
|---|---|---|
| `sp-on` | **2** | 150 |
| `sp-off` | **0** | 135 |
| `hardened` | **2** | 150 |
| `unhardened` | **0** | 148 |

0-vs-nonzero on the measured quantity, with the control non-zero on both sides.
A run whose control had fallen to zero would be a broken measurement, not a
clean artefact.

## 5. Residue

| fixture | absolute build-host path in the bytes | control string | forbidden marker |
|---|---|---|---|
| `dbg-on` (`-g`) | **1** (the build directory, in `.debug_line_str`) | found | found |
| `dbg-off` (`-g0`) | 0 | found | found |
| `hardened` | 0 | found | found |
| `unhardened` (`-g`) | **1** | found | found |

The control string is the extractor's 0-vs-nonzero control: it is compiled into
every fixture and must always be found. If it is not, the extractor has stopped
working and the run reports `INCOMPLETE` rather than clean.

Note that the interpreter path `/lib64/ld-linux-x86-64.so.2` is in `.interp` of
every dynamic executable. A detector that flags any absolute path flags every
binary on the system, so distribution prefixes are excluded and the shapes are
per-user and per-build-host directories.

## 6. What the table does not cover

- **`-static-pie`.** Not built, not measured, not claimed. The reader classifies
  `ET_DYN` without `PT_INTERP` but with `DF_1_PIE` as `exec-static-pie`, and
  that classification is untested against a real one.
- **Non-x86-64 and ELF32.** `readElf` returns `supported: false` with a reason;
  callers must treat it as "could not look".
- **clang.** The whole table is gcc 13.3.0. clang-18 is installed here and was
  not used for it.
- **A protector build with no eligible function.** `stack-protector` would read
  `ABSENT`, correctly for the artefact and misleadingly for the flag. The fixture
  that produced the rule has a 64-byte stack array and a `strcpy` into it; the
  limitation is stated in the finding's own note rather than hidden.

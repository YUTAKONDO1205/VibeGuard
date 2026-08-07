# elf-verifier — where did this come from?

Every other check in `compiler/` follows a **disappearance**: a property the
source states, and whether it is still there afterwards. This one follows the
other direction. Something is in the artefact. Which permitted origin put it
there — and if none of them did, say so.

The hard part is not detection. It is that almost everything new in a C++
artefact is **correct**: a template instantiation, a vtable, a typeinfo string,
a closure's `operator()`, a thunk for a multiply-inherited base, a
`_GLOBAL__sub_I_*` for one namespace-scope object, three hundred `__asan_*`
imports because someone passed `-fsanitize=address`. A detector that reports
those is a detector that gets switched off in its first week.

So the baseline comes first and the classifier second.

## 1. The baseline, and why it has three keys

`baseline.mjs` compiles a near-empty translation unit and records everything
the toolchain put in the result without being asked by the source. That set is
the only deduction the classifier is allowed to make.

The first version of this was "compile an empty unit once, subtract it from
everything". That is wrong, and wrong in the direction that hides things: what
an empty unit introduces is a property of the toolchain **and the flags** **and
the link form**.

| Change | What appears | If a single-key baseline is deducted |
|---|---|---|
| `-fstack-protector-strong` | `__stack_chk_fail`, `__stack_chk_guard` | written off as "toolchain" |
| `-D_FORTIFY_SOURCE=2` | `__memcpy_chk`, `__sprintf_chk`, … | written off |
| `-fsanitize=address` | `asan.module_ctor`, a `.preinit_array` slot, ~5900 symbols | written off |
| `-O0` → `-O3` | different crt helpers, `.llvm.N` and `.cold` suffixes | written off |
| dynamic → `-static` | the whole libc surface moves from UND to defined | written off |
| exec → `-shared` | `_start`, `Scrt1.o` and `PT_INTERP` disappear | the reverse: false positives |

So the key is `(toolchain digest, flag set, link form)`:

- **toolchain digest** — SHA-256 over the driver's bytes *and* the C runtime
  startup objects (`Scrt1.o`, `crti.o`, `crtbeginS.o`, …) and `libstdc++.so`. A
  distribution can ship a new `crtbeginS.o` without changing what
  `clang++ --version` prints.
- **flag set** — the normalised command line, order preserved (`-O0 -O3` and
  `-O3 -O0` are different compilations). A flag carrying an absolute path, such
  as `-fpass-plugin=/…/libMarkerPass.so`, is rewritten to
  `basename@sha256:<digest>`: no absolute path reaches a record, and two plugins
  with one name and different bytes become two different keys.
- **link form** — read back out of the artefact's own header, not taken from the
  command line, so a build whose flags and whose output disagree is caught
  instead of trusted.

There is no nearest-match lookup. **The only two answers are the right baseline
and none**, because every kind of approximate match is a way of deducting a
measurement that was never taken.

Baselines are written under `~/vg-lab/introduction-analysis/baseline/`, never
inside the repository.

## 2. The classifier

`classify.mjs` sorts four kinds of item — defined symbols, undefined symbols
(the external-call surface), `.init_array`/`.preinit_array`/`.fini_array` slots,
and sections — into six origins:

| Origin | Decided by |
|---|---|
| `toolchain-derived` | present in the baseline for **this** key, or an ELF/psABI section name |
| `linker-generated` | `_DYNAMIC`, `__bss_start`, …; `__start_X`/`__stop_X` **when section `X` exists** |
| `dependency-derived` | the symbol really resolves in a `DT_NEEDED` library's `.dynsym`, on disk |
| `runtime-support` | a sanitiser/EH/fortify grammar **and** a flag that asked for it |
| `generator-derived` | an Itanium ABI construct (vtable, VTT, typeinfo, thunk, guard, closure, static initialiser) whose source names are all in the preprocessed unit |
| `source-derived` | a name fully attributable to the preprocessed translation unit |

Then one of three verdicts: `Explained`, `Unexplained`, `Unresolved`.

### The rule that matters

Every rule returns *matched*, *did-not-match*, or **could-not-run**. An item no
rule matched is `Unexplained` only if no rule *could-not-run*; otherwise it is
`Unresolved`. `Unresolved` is never rounded to `Explained`.

Collapsing those two is how a checker reports "clean" for an artefact it never
managed to look at — and, in the other direction, how a missing baseline turns
into a wall of false positives. Both come from the same collapse. Measured:
classify the thunk control without its declared source and 74 items move from
`Explained` to `Unresolved`, with `Unexplained` still 0. It abstains; it does
not accuse.

### Attribution is against the *preprocessed* unit

`typeid(*p).name()` produces `_ZNKSt9type_info4nameEv`, and neither `type_info`
nor `name` is written in the `.cc`. Asking the raw file rejects it. Asking the
preprocessed translation unit accepts it, and accepts nothing the compiler did
not also see.

Names are read with a grammar over the Itanium ABI encoding, not with a
demangler — what is needed is the *list of identifiers a name is built from*, so
each can be looked for in the unit. This is where the sharpest bug lived: the
`2` in `_ZN5ShapeD2Ev` is a destructor variant, not a length prefix, and reading
it as one produced the component `Ev`, which is in no source file. Twenty-six
correct constructors and destructors came out as `VG-INTRO-001`. The
`<ctor-dtor-name>` production and the row for it in `test-units.mjs` are that
bug's headstone.

## 3. Findings

| Id | Severity | What |
|---|---|---|
| `VG-INTRO-001` | high | a symbol no permitted origin explains |
| `VG-INTRO-002` | high | an external call resolving in no authorised `DT_NEEDED` library |
| `VG-INTRO-003` | critical | an initialiser that runs before `main` and nothing explains |
| `VG-INTRO-004` | critical | an executable section nothing explains |

`VG-INTRO-003` is deliberately the strictest rule in the file. Being an
*explained symbol* is not enough to be an explained *initialiser*: putting an
otherwise ordinary function into `.init_array` is the whole attack. An entry
passes only if it is a static initialiser, a sanitiser module constructor, a
baseline entry, or a function from a unit whose source contains
`__attribute__((constructor))`. That last tie is at translation-unit
granularity, not function granularity — a unit that declares one constructor and
ships two slots passes. Stated, not hidden; closing it needs the AST, which is a
different component's observation point.

## 4. Reading ELF

Nothing here parses another program's output. GNU readelf 2.42 prints a PIE as
`DYN (Position-Independent Executable file)`; llvm-readelf-18 prints
`DYN (Shared object file)` for the same bytes. That is measured, in case
`TOOL-1` of the control run. A check written against either string changes its
answer on a toolchain upgrade.

Verdicts come from structural fields, and every record says which:

- **PIE** = `Elf64_Ehdr.e_type == ET_DYN` **and** `DT_FLAGS_1 & DF_1_PIE`. Both
  halves matter: every shared library is `ET_DYN` too.
- **Full RELRO** = `PT_GNU_RELRO` **and** eager binding, where eager binding has
  three legal spellings (`DT_BIND_NOW`, `DT_FLAGS & DF_BIND_NOW`,
  `DT_FLAGS_1 & DF_1_NOW`) and a linker may emit only one. Accepting one is how
  a fully hardened binary gets reported as partial RELRO.
- **NX** = `PT_GNU_STACK` present **and** `PF_X` clear. Absent is a failure, not
  an abstention: with no `PT_GNU_STACK` the kernel falls back to an executable
  stack.

The external-call surface is keyed on the version-stripped name. `.symtab`
spells an undefined versioned import `_Znwm@GLIBCXX_3.4` and `.dynsym` spells
the same import `_Znwm`; keying on the raw string reported four calls as eight
findings, measured in `POS-7`. The versions seen are kept on the entry.

`.init_array` resolution has three shapes and getting any of them wrong yields
an empty list, which reads as "no initialisers run" — the worst available false
negative. `ET_REL`: `.rela.init_array` names the symbol. `ET_EXEC`: the slot
holds the address. `ET_DYN`: the slot is zero and `R_X86_64_RELATIVE` carries
the address in `r_addend`.

## 5. Running it

```sh
node run-controls.mjs                 # builds everything, checks every case, exit 0 iff all pass
node test-units.mjs                   # grammar and canonical-record unit checks

node baseline.mjs --build --form exec-pie -- -O0 -g0
node baseline.mjs --list
node classify.mjs --artifact a.out --source a.cc --json out.json -- -O0 -g0
```

Exit codes are `compiler/schema/interfaces.md` section 7: `0` clean, `2`
findings, `3` a check could not be completed (any `Unresolved` item, or a
baseline key with no match), `4` unreadable artefact. **`3` is never `0`.**

Control sources are generated, not tracked (`node controls.mjs --write <dir>`),
for the reason measurement inputs always are: they get compiled into
machine-specific objects next to themselves, and this tree is published.

## 6. What is not covered

- **`-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` have their own key but
  no measured content.** The near-empty translation unit has no stack array and
  no fortifiable call, so that baseline is identical in content to the plain
  `-O0` one — measured, `defined=27 undef=7 sections=29 init=2` for both. In a
  real protector build `__stack_chk_fail` is explained by resolving in
  `libc.so.6`, not by the baseline. The key still refuses cross-deduction; the
  content half of the claim is not demonstrated for those two flags. Widening
  the baseline translation unit past "near-empty" would fix it, at the cost of
  the baseline no longer being purely toolchain-attributable.
- **`exec-static`.** The baseline would hold libc's startup path but not the
  parts a real program drags in, so those come out `Unresolved`. Not measured,
  not claimed.
- **Non-x86-64, non-ELF64-LSB.** `readElf` returns `supported: false` with a
  reason; callers must treat that as "could not look".
- **LTO.** Not measured. `.llvm.N` suffix stripping exists, but no control
  exercises a `-flto` link.
- **A translation-unit-level constructor tie**, as above.
- **`compiler/pass-instrumentation/`** is another component's. This one only
  *reads* the plugin it builds, as positive control `POS-2`.

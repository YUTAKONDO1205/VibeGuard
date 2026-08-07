# Introduction analysis (`VG-INTRO-0NN`)

The mirror of first-loss. The observer next door asks when a security property's
effect *disappeared* and which pass, on which IR unit, removed it. This asks
when something *appeared* that was not there before, where it came from, and
whether any permitted origin explains it.

Two halves, and they answer different questions:

| | Question | Where it runs |
|---|---|---|
| **Pass level** | Which `(pass, IR unit)` pair first introduced this, and what happened to it afterwards? | inside the compiler, `libIntroductionObserver.so` |
| **Artefact level** | Is there anything in the object that no permitted origin accounts for? | `cli/intro-scan.mjs`, over a compiled object |

Both are needed, because neither sees what the other sees. Module-level inline
assembly never enters LLVM's symbol table, so a symbol, a section and an
`.init_array` slot can all arrive in the object with the compiler's own model of
the translation unit showing no trace of them — an IR-only detector is blind to
exactly the shape an assembler wrapper would use. Equally, the object cannot say
*which pass* turned a loop into a `memset`; only the pipeline can.

## The thing that would have sunk this, and what was done about it

Compiling one small C++ file produces about a hundred and fifty symbols the
source never names. Measured on this component's own negative fixture, with
`clang++-18 -std=c++17 -O0`: **206 introduced elements**, of which the source
names three. Three vtables, two VTTs, a construction vtable, four typeinfo
objects, four typeinfo names, seven virtual thunks, a guard variable, a lambda
call operator, fifty-five template instantiations, ten unwind tables, a
personality reference, fifty per-function executable sections, and calls into
the C++ ABI runtime.

A detector that reports "something appeared that the source did not ask for"
therefore reports two hundred and three things about a file that is entirely
normal, on every build, for ever. That is not a noisy detector; it is a broken
one.

So the toolchain baseline is not a refinement to add later. It is the component,
and the detector is the small part that runs after it. **Measured result on the
negative fixture: 0 Unexplained, 0 Unresolved, at both `-O0` (206 elements) and
`-O2` (52 elements).**

There is no per-fixture exception list here and no "known noisy symbol" set. If
the negative fixture produces an Unexplained element, the rules are wrong and
the rules get fixed — an exception list would make the fixture pass while
leaving the detector exactly as broken, behind a green tick.

### How the baseline is built

Two halves, and both are needed:

1. **Measured.** The front end is asked what it produced from *this exact
   compilation* — same compiler, same flags, same source — by running it again
   with `-Xclang -disable-llvm-passes -emit-llvm`. Every name in that dump is
   something the front end emitted, which is a fact about this build rather than
   a guess about builds in general.
2. **Structural.** Names whose shape the C++ ABI or LLVM defines. `_ZTV` is a
   vtable whether or not this build happened to contain one. This covers what
   appears only after the front end — codegen's unwind tables, the optimiser's
   clones, the assembler's temporaries — and generalises to classes nobody had
   written when the rules were.

Neither alone is enough. Measurement cannot explain a `.cold` clone that no
earlier stage contained; shape cannot explain `intro_negative_main`, which is
just a name.

**With no measured baseline, nothing is Explained and nothing is Unexplained —
everything the structural rules do not cover is `Unresolved`, and the run exits
3.** An unavailable baseline must never read as a clean result.

## Origins and verdicts

Six permitted origins, in the order the rules are tried:

| Origin | What it means |
|---|---|
| `linker-generated` | the link editor defines it; no input object can contain it |
| `runtime-support` | an entry point of a runtime the compiler references without the source naming it, including the libcalls LLVM materialises from IR that names no function |
| `toolchain-derived` | the compiler's own work: ABI entities, static-init machinery, template instantiations, lambdas, codegen artefacts, optimiser clones, assembler temporaries |
| `dependency-derived` | mangled into a namespace the standard reserves to the implementation, or exported by a declared dependency |
| `generator-derived` | defined in a file the policy lists as machine-written |
| `source-derived` | the front end emitted this name from the translation unit |

An element with one of these is **Explained**. With none, **Unexplained** — a
finding. When the evidence needed to decide was not collected, **Unresolved** —
exit 3, never conflated with 0.

The ordering matters. Structural rules run before the measured front-end set,
because the front-end set contains the ABI entities too and would report a
vtable as source-derived: true in the sense that the class was in the source,
and useless as an origin, because the question is *who put this here* and for a
vtable the answer is the compiler.

## Findings

| Id | Severity | Fires when |
|---|---|---|
| `VG-INTRO-001` | high | a **defined symbol** is Unexplained |
| `VG-INTRO-002` | high | an **external call** — a call-shaped relocation at a code offset, or an IR call site whose callee has no body — is Unexplained, or unapproved under `allowlist` mode |
| `VG-INTRO-003` | critical | a **static initialiser** (an `.init_array` slot, or an `@llvm.global_ctors` entry) is Unexplained. Critical because it runs before `main` |
| `VG-INTRO-004` | high | an **executable section** is Unexplained |

An executable section is judged by what it holds, never by its name: `-ffunction-sections`
produces one `.text.<mangled name>` per function, and a rule that only knew the
standard names would report all fifty. A section's verdict is its contents'
verdict — which also means a section cannot be excused by choosing a
respectable-looking name.

## The oracle rule, on both sides

interfaces.md §4: count the call site, never the symbol name.

* **In IR** an external call is a `call`/`invoke` whose callee has no body. A
  `declare` line is not one, and a name search would keep reporting it long
  after the last call to it was deleted.
* **In an object** a call site is a *call-shaped relocation at a code offset* —
  an instruction — not the presence of an undefined symbol in the symbol table.
  A symbol with no relocation against it is a reference that survived, not a
  call.

Both directions are tested in `test/oracle.test.mjs`, including the
0-vs-nonzero pair: declaration present, call sites zero, control's call sites
nonzero.

## The state series

interfaces.md §3 fixes six states, and `INTRODUCED` is not one of them. That is
not an omission to work around: it is the name of a **transition**,
`ABSENT -> PRESENT`, and the states either side already exist. Later arrivals
have a state of their own, `REINTRODUCED`, because by then the element has a
history.

The `ABSENT` entry is measured, not assumed. Every observation enumerates a
whole scope, so when an element first appears in scope S at seq *k*, the
previous observation of S at seq *j* is a point at which the scope was
enumerated and the element was not in it. The entry carries seq *j*.

An element already present at the first observation of its scope gets no
`ABSENT` entry and is marked `atEntry`: there is no point at which the plugin
saw the scope without it, so the front end put it there and blaming the first
pass to run would be an attribution the measurement does not support.

Measured on `subjects/passes/introduced.c` with `clang-18 -O2`:

```
intro_pass_subject       extcall llvm.memset.p0.i64  ABSENT@LoopIdiomRecognizePass -> PRESENT@LoopIdiomRecognizePass
intro_pass_subject_two   extcall llvm.memset.p0.i64  ABSENT@LoopIdiomRecognizePass -> PRESENT@LoopIdiomRecognizePass
intro_pass_reintroduced  extcall llvm.memset.p0.i64  PRESENT@... -> LOST@InstCombinePass -> REINTRODUCED@LoopIdiomRecognizePass
```

The first two rows are why the attribution is a `(pass, IR unit)` pair and not a
position in a flat pass list: **one pass, two callbacks, two different units,
two different attributions**. A `P0..Pn` model would have to pick one and be
wrong about the other.

The third row is why the whole series is kept. A checker that stopped at the
first `PRESENT -> LOST` would report a loss that `LoopIdiomRecognizePass` had
already undone — a false positive with a plausible story attached.

The plugin writes both its conclusion (`SUMMARY`) and its evidence (`HIST`), and
`lib/states.mjs` re-runs the same state machine over the evidence from a
separate implementation in a separate language. `crossCheck` compares them; a
disagreement is reported as a disagreement rather than believed. Measured: 0
disagreements over 20 elements.

## Running it

```sh
# object level: compile, subtract, report
node cli/intro-scan.mjs subjects/negative/normal_cxx.cpp --opt -O0 --std c++17
node cli/intro-scan.mjs subjects/positive/injected.c --opt -O2

# pass level: build the plugin, measure, read the log
tools/live.sh all
node cli/intro-passes.mjs "$INTRO_LAB_DIR"/passes.tsv
```

`tools/live.sh` also does the non-invasiveness check: the same source compiled
with and without the plugin, compared byte for byte. The observer registers
callbacks only — it adds no pass, returns no analysis result and mutates
nothing — and this is what turns that claim into a measurement.

Builds go to `$INTRO_BUILD_DIR` (default `$HOME/vg-build/pass-introduction`) and
measurements to `$INTRO_LAB_DIR` (default `$HOME/vg-lab/pass-introduction`).
Never under `compiler/` — interfaces.md §1.

## Tests

```sh
node --test compiler/pass-instrumentation/introduction/test/*.test.mjs
```

The glob is expanded by the shell, not by node: passing the directory throws
`MODULE_NOT_FOUND` on current runtimes.

Two suites need a toolchain. **They fail without one — they do not skip.** A
suite that skipped itself reports the same green as a suite that passed, which
is the failure this component exists to complain about one level up. Setting
`VG_INTRO_ALLOW_SKIP=1` authorises the skip, and every skipped case is then
named in the output.

On a Windows checkout with the toolchain in WSL, run the live suites from
PowerShell rather than from git bash. Git bash rewrites a POSIX-looking value in
the environment into a Windows path before the process ever sees it, so
`INTRO_BUILD_DIR` and `INTRO_LAB_DIR` arrive pointing at the git-bash
installation root instead of at the distribution — which sends the build
somewhere the measurement then cannot find. Measured; it cost a debugging round
here.

## The counting contract

Every runner prints `inputs=N checked=N skipped=S` and exits non-zero when N is
0, unless `--allow-empty` was passed — and then prints `allowEmpty=1`, so the
claim is on the record. The empty case is decided before any tool is touched,
so it cannot be argued down to 0 by a later step reporting nothing wrong.

```
$ node cli/intro-scan.mjs                      # no inputs
intro-scan: inputs=0 checked=0 skipped=0
intro-scan: no inputs were found, ... This is exit 3 (INCOMPLETE), not exit 0
$ echo $?
3
```

Every skip carries a name and a reason, and `render()` lists all of them.

## Policy

Introduction settings live in their own file, named with `--intro-policy`,
because `compiler/schema/policy.schema.json` sets `additionalProperties: false`
at its top level: a `.vgpolicy.json` carrying an `introduction` key is rejected
as malformed (exit 4) by the driver that validates it. Folding these settings in
means adding the key to that schema, which belongs to another component. The
defaults in `lib/policy.mjs` are what runs when no file is named.

## Layout

```
CMakeLists.txt              the plugin build (out of band; never npm)
IntroductionObserver.cpp    plugin entry: registers callbacks, nothing else
Census.h/.cpp               the element census, the state machine, the log
Config.h/.cpp               INTRO_* environment configuration
lib/count.mjs               the counting contract
lib/lineage.mjs             clone lineage and ABI name shapes
lib/origins.mjs             the origin taxonomy and its rules
lib/baseline.mjs            the subtraction, and the two-pass section rule
lib/irsyms.mjs              reading IR: the front-end set, and call sites
lib/elf.mjs                 reading an object: symbols, relocations, sections
lib/introlog.mjs            reading the plugin's log
lib/states.mjs              the state machine again, independently, plus crossCheck
lib/findings.mjs            VG-INTRO-001..004
lib/policy.mjs              the introduction policy
lib/toolchain.mjs           reaching the compiler from either side of the mount
cli/intro-scan.mjs          the artefact-level runner
cli/intro-passes.mjs        the pass-level reader
tools/live.sh               build, measure, and check non-invasiveness
subjects/negative/          C++ with templates, a virtual class, RTTI, a lambda
subjects/positive/          an injection the front end never declared
subjects/passes/            the pass-level subjects and their control
```

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.

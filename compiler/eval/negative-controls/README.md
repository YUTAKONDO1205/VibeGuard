# Negative Controls for introduction detection

the design plan section 23.1 asks for Negative Controls, and it is specific about what they are:
**normal compiler output**. Not benign programs — benign *compiler artefacts*.

That specificity is the whole point. `VG-INTRO-001..004` report elements that
appeared in an object file with no permitted origin, and most of what appears in
an object file has no line of source behind it. Compiling one small C++
translation unit produces on the order of two hundred elements the source never
names: vtables, typeinfo objects, thunks, template instantiations, closure
types, guard variables, unwind tables, assembler temporaries. Every one of them
is the compiler doing its job. A detector without a toolchain baseline reports
all of them, on every build, for ever — and that is not a noisy detector, it is
a broken one.

So this corpus does not ask "does the detector fire". It asks: **does it stay
silent on each kind of ordinary compiler output, separately, so that a failure
names the kind that caused it.**

## The seven structures, one fixture each

| | Fixture | Isolates |
|---|---|---|
| NC-01 | `nc01_template_instantiation.cpp` | template instantiation |
| NC-02 | `nc02_vtable.cpp` | vtable, VTT, construction vtable |
| NC-03 | `nc03_rtti.cpp` | RTTI in use: `typeid`, `dynamic_cast`, `__dynamic_cast` |
| NC-04 | `nc04_lambda.cpp` | closure types, in both mangling encodings |
| NC-05 | `nc05_thunk.cpp` | non-virtual, virtual and covariant-return thunks |
| NC-06 | `nc06_static_initializer.cpp` | dynamic initialisation, guard variables, `constructor`/`destructor` attributes |
| NC-07 | `nc07_sanitizer.c` | sanitizer instrumentation (`-fsanitize=address`, `-fsanitize=undefined`) |

Each is deliberately narrow. A file that exercised all seven would report "a
finding" and leave the reader to work out which structure caused it; seven files
report *which one*.

`NC-07N` runs the NC-07 source with **no** sanitizer flag. It is the lane
control: it separates "the instrumentation pass introduced something the
baseline cannot explain" from "this source did", which neither instrumented case
can do alone.

## Why NC-07 is the one that decides anything

Six of the seven structures are emitted by the **front end**. The measured half
of the toolchain baseline is taken by re-running the same compilation with
`-Xclang -disable-llvm-passes -emit-llvm`, so it contains them, and the
subtraction finds them there.

Sanitizer instrumentation is not. AddressSanitizer is an LLVM pass: it runs
*after* the point at which the baseline is measured. Everything it adds is, from
the baseline's point of view, something that appeared out of nowhere between the
measurement and the object — which is a precise description of what
`VG-INTRO-001..004` exist to report. NC-07 is therefore the case that tells you
whether the **structural** half of the baseline is real or decorative.

## Positive controls, and why they are in the same run

Seven negative controls reporting `Unexplained = 0` is exactly what a switched-off
detector reports. The two are indistinguishable from the negative controls alone.

So every configuration family carries a positive control compiled with the **same
compiler and the same flags in the same run**:

| | Fixture | Configuration |
|---|---|---|
| PC-01X / PC-01 | `pc01_unexplained_injection.c` | C++17, and C |
| PC-01A / PC-01U | same source | `-fsanitize=address`, `-fsanitize=undefined` |
| PC-02 | `pc02_respectable_section.c` | injection into a section named like ordinary `-ffunction-sections` output |

A run in which the negative controls are clean and a paired positive control is
*also* clean is reported as **NOT ESTABLISHED**, not as a pass.

PC-02 exists because PC-01 could be passed by a rule that refuses unfamiliar
`.text.*` section names — a rule that is defeated in one line, since
`-ffunction-sections` produces dozens of them per object. PC-02's section is
named `.text._ZN4pc026Widget6renderEv`, indistinguishable from legitimate
codegen output, and the injected symbol inside it is still unexplained.

## Probes: PC-03 and PC-04

These are **not** controls and are never scored. They ask what happens when the
injected symbol is *named* like something the ABI requires the compiler to emit
(`_ZTV...`), which rule `R3.abi-entity` in `lib/origins.mjs` explains by shape.

* **PC-03** — ABI-shaped name, and the body calls `dlopen`.
* **PC-04** — ABI-shaped name, and the body calls nothing; it writes to a global
  this translation unit owns, which is what a payload that clears a flag would do.

Whatever these produce is the measurement. A clean result is a false negative to
write down, not a fixture to adjust — and the repair is not obvious, because
`R3.abi-entity` is what keeps every vtable in every future C++ object out of the
report. The trade belongs in the record.

## Running it

```sh
node compiler/eval/negative-controls/run-negative-controls.mjs [--crosscheck]
```

Results are written to `$LAB/_results-wave2/negative-controls/`
(`--results` to change it, `--no-write` to suppress). Builds and intermediates go
to `$INTRO_LAB_DIR/negative-controls`; never under `compiler/` — interfaces.md §1.

`--crosscheck` additionally runs the shipped `cli/intro-scan.mjs` on every case
it can take and compares the counts. It cannot take the sanitizer cases, because
that CLI accepts `--opt` and `--std` and no other compiler flag; the runner
therefore drives the same library modules the CLI drives, and checks the two
agree wherever both can run rather than asserting they would.

## How to read a failure

Three failures, three different meanings, and the runner does not conflate them:

* **`FALSE POSITIVE: n Unexplained element(s) on normal compiler output`** — the
  detector reported the compiler. This is the failure the corpus exists to find.
  Fix the rules in `lib/origins.mjs`. **Do not add the symbol to an exception
  list**, and do not move a threshold: that makes the fixture green while leaving
  the detector exactly as broken, behind a tick.
* **`the fixture no longer exercises <structure>`** — the subject was optimised
  away and the case tested nothing. Its `Unexplained = 0` means nothing. Fix the
  fixture, not the expectation.
* **`n Unresolved element(s) — not the same as explained`** — the run could not
  decide. Exit 3 territory; never counted as clean.

Exit codes: `0` all expectations met · `2` an expectation was not met · `3` no
case matched · `4` bad arguments · `5` a tool or compilation failed.

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.

# clang-plugin — `IntentGate`

A Clang **AST plugin** that takes lexical findings and decides, per finding,
whether the AST agrees:

| Verdict | Meaning |
|---|---|
| `Confirmed` | a real call to the flagged function is spelled at that exact location |
| `Rejected` | that location does not denote the effect — a string literal, a comment, a declaration nobody calls, a preprocessed-out block |
| `Refined` | the location is not the call, but the call exists and this location explains how to reach it — a macro body, a taken address, a declaration of a function that *is* called |
| `Deferred` | the check could not be run. Never merged into `Rejected`. |

It then turns each surviving finding into a **Derived Requirement** — a property
id, a kind, a scope and a set of observation checkpoints — which is what the
later stages of the toolchain can actually be asked about.
**[`DERIVATION.md`](DERIVATION.md) is the specification of that map** and is the
substance of this component; this file is how to build and run it.

Sources here, builds and measurements on the Linux filesystem
(`compiler/schema/interfaces.md` §1). Nothing under `compiler/` is a build
product or a measurement.

---

## Build

```sh
cmake -S compiler/clang-plugin -B ~/vg-build/clang-plugin -G Ninja \
      -DCMAKE_CXX_COMPILER=clang++-18 \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir) \
      -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang
ninja -C ~/vg-build/clang-plugin
```

Two things that are not optional:

- **`find_package(LLVM REQUIRED CONFIG)` takes no version argument.** LLVM 18's
  config-version file rejects a bare `18` as incompatible with `18.1.3`. Point
  at the tree with `-DLLVM_DIR` / `-DClang_DIR`.
- **`-fno-rtti`.** LLVM and Clang are built without RTTI; a plugin built with it
  does not link against them.

The plugin links **nothing** from LLVM or Clang. It is `dlopen`'d into a clang
process that already has `libclang-cpp` resolved, and undefined symbols in a
`MODULE` library are satisfied from the host process at load time. Linking a
second copy in is how a plugin ends up with two command-line option registries.
This is measured, not assumed — the load succeeds in §"Measured" below.

## Run

```sh
clang-18 -fplugin=$HOME/vg-build/clang-plugin/libIntentGate.so \
  -Xclang -add-plugin -Xclang intent-gate \
  -Xclang -plugin-arg-intent-gate -Xclang findings=findings.json \
  -Xclang -plugin-arg-intent-gate -Xclang rules=compiler/clang-plugin/rules/default-rules.json \
  -Xclang -plugin-arg-intent-gate -Xclang root=/path/to/fixtures \
  -Xclang -plugin-arg-intent-gate -Xclang out=record.json \
  -c input.c -o input.o
```

| Argument | |
|---|---|
| `findings=<path>` | **required.** interfaces.md §2 findings (see the schema note below). Absent ⇒ the plugin errors out rather than silently doing nothing. |
| `rules=<path>` | rule table. Defaults to the table compiled in, which matches `rules/default-rules.json`. |
| `root=<dir>` | every path in the record is relative to this. Defaults to the main file's directory. |
| `out=<path>` | where to write the record. Absent ⇒ diagnostics only. |
| `quiet` | suppress the per-finding warnings. |

### The trap, stated plainly

`-plugin` and `-add-plugin` are not two spellings of the same thing. All three
rows below are measured (§7 of `measure.sh`):

| Invocation | exit | object file | gate ran |
|---|---|---|---|
| `-fplugin=… -Xclang -add-plugin -Xclang intent-gate` | 0 | **produced** | yes |
| `-fplugin=…` alone, no `-add-plugin` | 0 | **produced** | **yes** |
| `-fplugin=… -Xclang -plugin -Xclang intent-gate` | 1 | **not produced** | — |

`-plugin` **replaces** the main frontend action, so codegen never runs. That is
not "the build mysteriously stopped emitting objects", it is the documented
meaning of the flag.

The middle row is worth knowing and is a consequence of a deliberate choice:
`getActionType()` returns `AddAfterMainAction`, which registers whenever the
**module is loaded**, so `-add-plugin` is not actually required. (The variant
that does require it is `CmdlineAfterMainAction`.) A gate that can be skipped by
forgetting a flag is not much of a gate, so this component takes the version
that cannot. The consequence, also measured: `-fplugin=libIntentGate.so` with
**no** `findings=` argument fails the compile with
`error: IntentGate: findings=<path> is required`. That is the fail-closed
behaviour working, not a bug — but it does mean loading this module into a build
you have not configured will stop it.

---

## Measure everything

```sh
bash compiler/clang-plugin/tools/measure.sh
```

Writes to `~/vg-lab/clang-ast-gate/`, appends every command and exit code to
`~/vg-lab/clang-ast-gate/run-log.txt`, exits `0` only if every assertion holds.
It rebuilds its own fixtures first, so it carries no state between runs.

### Measured — clang 18.1.3, Ubuntu 24.04 (WSL2), 2026-08-07

**Classification.** Nine fixtures, every verdict matching
`tools/expected.json`:

| Fixture | Line | Verdict / reason | Sites |
|---|---|---|---|
| `confirmed.c` | 6 | `Confirmed / direct-call` | `confirmed.c:6@run_report` |
| `rejected.c` | 6, 7 | `Rejected / inert-lexeme` | — |
| `refined_macro.c` | 3 | `Refined / macro-expansion` | `refined_macro.c:8@via_alias` |
| `refined_macro.c` | 4 | `Refined / macro-expansion` | `refined_macro.c:13@via_wrapper` |
| `refined_fnptr.c` | 5 | `Refined / address-taken` | `refined_fnptr.c:9@main` |
| `rejected_more.c` | 3 | `Rejected / declared-never-called` | — |
| `rejected_more.c` | 8 | `Rejected / no-referent` | — |
| `mixed.c` | 6 | `Rejected / inert-lexeme` | — |
| `mixed.c` | 12 | `Confirmed / direct-call` | `mixed.c:12@main` |
| `wipe.c` | 10, 19 | `Confirmed / direct-call` | `wipe.c:10@login`, `wipe.c:19@control` |
| `astonly_alias.c` | 1 | `Rejected / inert-lexeme` | — (call surfaces in `astOnly`) |

`mixed.c` is the one to read first: a rejected string literal and a confirmed
call **in the same file**, which is what makes "the verdict is per location"
a measurement rather than a design intention.

**Positive controls.** Without these the table above is consistent with a
classifier that returns constants.

| Control | Result |
|---|---|
| (A) `rejected.c` line 7 rewritten from a string literal into a real call | `Rejected / inert-lexeme` → `Confirmed / direct-call` |
| (B) the same finding moved from `confirmed.c:6` to line 4 (the signature) | `Confirmed / direct-call` → `Rejected / no-lexeme` |
| (d) one verdict field edited in a record | `evidenceDigest` no longer reproduces |
| (e) `check-verdicts.mjs` given a tampered record | exits 2 |
| (f) `check-verdicts.mjs` given an unknown fixture | exits 3, never 0 |

Control A changes exactly one line of source; nothing else in the fixture, the
findings file, or the invocation differs.

**Non-invasiveness — 48/48 object files byte-identical with and without the
plugin.** Eight fixtures × six modes (`-O0 -O1 -O2 -Os` as C, `-O0 -O2` as C++),
compared by SHA-256. Full table:
`~/vg-lab/clang-ast-gate/results/sha256.tsv`.

That equality only means something if the comparison can detect a difference, so
three controls run alongside it:

| Control | Result |
|---|---|
| (a) the same compile run twice, no plugin | identical — so clang is deterministic here and the equality is not noise |
| (b) `-O0` vs `-O2` of the same file | **differ** — the comparison sees codegen changes |
| (c) `rejected.c` vs its one-line control variant | **differ** — the comparison sees source changes |

Conclusion, stated as measured rather than as expected: **on this toolchain an
`AddAfterMainAction` AST plugin does not change the emitted object.** Two
caveats that are part of the claim: the plugin emits warnings, never errors — an
error would stop codegen and no object would be produced at all; and this was
measured on the eight fixtures and six modes above, not proved in general.

**Fail-closed.** Loading the plugin with no `findings=` argument exits 1 rather
than compiling cleanly (`error: IntentGate: findings=<path> is required`, no
object file). A gate that was asked for and could not run must not look like a
gate that ran and found nothing (interfaces.md §7).

**Record.** Canonical per interfaces.md §5 — re-serialising `mixed.gate.json`
with an independent canonicaliser (sorted keys, no whitespace, integers only)
reproduces the file byte for byte, the recorded `evidenceDigest` recomputes, and
no absolute path appears anywhere in it.

### Reproducing a single fixture by hand

```sh
FIX=$HOME/vg-lab/clang-ast-gate/fixtures
bash compiler/clang-plugin/tools/make-fixtures.sh
node compiler/clang-plugin/tools/lexscan.mjs $FIX/mixed.c --root $FIX > /tmp/f.json
clang-18 -fplugin=$HOME/vg-build/clang-plugin/libIntentGate.so \
  -Xclang -add-plugin -Xclang intent-gate \
  -Xclang -plugin-arg-intent-gate -Xclang findings=/tmp/f.json \
  -Xclang -plugin-arg-intent-gate -Xclang root=$FIX \
  -c $FIX/mixed.c -o /dev/null
```

---

## What is in here

| Path | |
|---|---|
| `DERIVATION.md` | **the Finding → Derived Requirement map.** The specification. |
| `src/Gate.h` | the shared vocabulary — `Rule`, `LexicalFinding`, `Verdict`, `Reason`, `DerivedRequirement` |
| `src/Classifier.{h,cpp}` | the AST inventory (ASTMatchers) and the classification rules |
| `src/Derivation.{h,cpp}` | verdict → requirement, scope, oracle count, property id |
| `src/Canonical.{h,cpp}` | interfaces.md §5 canonical JSON and SHA-256 |
| `src/Findings.{h,cpp}` | input parsing, the built-in rule table, enum spellings |
| `src/IntentGate.cpp` | the plugin: registration, arguments, diagnostics, the record |
| `rules/default-rules.json` | the rule table |
| `tools/make-fixtures.sh` | writes the fixtures to `~/vg-lab/clang-ast-gate/fixtures` |
| `tools/lexscan.mjs` | a deliberately naive lexical scanner — the input generator |
| `tools/expected.json` | the expected classification of every fixture |
| `tools/check-verdicts.mjs` | compares a record against it; 0 / 2 / 3 |
| `tools/measure.sh` | runs all of the above and every control |

`tools/lexscan.mjs` is naive **on purpose**: it matches over raw text with no
comment or string blanking, so it emits exactly the false positives the gate has
to reject. Worth naming the difference from what VibeGuard ships: the shipped C
rules in `packages/rules/src/rules/lang-c.ts` already call
`blankCommentsAndStrings`, so in the shipped pipeline the `Rejected` class
arrives from the cases blanking cannot reach — a declaration nobody calls, an
identifier inside `#if 0`, a macro body. `rejected_more.c` and
`refined_macro.c` are in the fixture set for exactly that reason.

---

## Schema gaps reported upward

`interfaces.md` says a component that needs a shape which is not there reports
it rather than inventing one. Three, none of them edited into that file:

1. **A finding has no line.** §2's `where` is
   `{ kind, path, unit, pass }`. A gate that classifies *a location* cannot
   address anything with that. Read here from `where.line` / `where.column`
   (top-level `line` / `column` accepted as an alias), and from `match` for the
   matched text. All three are extensions.
2. **No namespace for an AST gate.** §2's owner table lists driver, plugin
   integrity, IR checkpoints, introduction analysis, link wrapper, artefact
   verifier. This component emits verdicts and requirements rather than findings
   and so claims none of the six — but if it should ever report a finding of its
   own, there is no id space for it.
3. **A finding does not identify the bytes it was computed from.** The gate
   re-lexes the file the compiler is currently reading; if the scanner ran over
   a different revision, every verdict is meaningless and **nothing detects it**
   (`DERIVATION.md` §7.5). A content digest of the scanned file, in the finding,
   would close this.

One more, about the rule table rather than the schema: **there is no shipped
C/C++ command-execution rule.** `VG-INJ-003` covers Python `os.system` /
`os.popen` and its `languages` list contains neither `c` nor `cpp`; nothing else
matches `system(` in C. `VG-CEXEC-001` / `-002` in `rules/default-rules.json`
are therefore gate-local ids, marked as such in that file. If a shipped rule
ever lands, replace them rather than leaving two ids for one construct.

## Licence

Apache-2.0 WITH LLVM-exception, as the rest of `compiler/` — see
`compiler/LICENSE`. It compiles against the Clang and LLVM development headers;
no LLVM source is vendored.

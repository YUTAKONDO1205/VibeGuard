# Finding → Derived Requirement

A lexical scanner says *"line 12 of `mixed.c` matched `system`"*. The rest of
this toolchain wants something else: a **property**, with a scope and an oracle,
that later observation points can be asked about. Nothing until now defined how
to get from the first to the second — `compiler/schema/interfaces.md` fixes the
shape of a finding (§2) and the shape of a property state (§3), and stops.

This file defines the map. It is written so that two people implementing it
independently get the same answer on the same input, which means every rule is
a predicate over things you can compute, and none of them says "judge from
context". Where something is genuinely not decidable, it is in
[Declared misses](#7-declared-misses) instead of being decided badly.

The map has two steps and they are separate on purpose:

```
  lexical Finding ──(1) classification, from the AST──▶ Verdict
  Verdict ─────────(2) derivation, from the rule + the AST──▶ Derived Requirement
```

Step 1 answers *is this real, and if so where*. Step 2 answers *so what must
hold, and where must it be checked*. Keeping them apart is what makes it
possible to say "this finding is real but the requirement it implies is
nothing", which is a sentence the toolchain needs and which a one-step mapping
cannot express.

---

## 1. Notation

Fixed for the whole file.

| Symbol | Meaning |
|---|---|
| `F = (r, p, ℓ, m)` | a lexical finding: rule id, path, line, matched text |
| `R` | the rule-table entry with `R.id = r` (`rules/default-rules.json`) |
| `T` | the **target**: the longest `t ∈ R.targets` that occurs as a substring of `m`. Undefined if none does. |
| `U` | the translation unit being compiled |
| `root` | the fixture root; every path in a record is relative to it (interfaces.md §5) |
| `rel(f)` | `f`'s path relative to `root`, or the sentinel `<outside-root>` |
| `Raw(f, ℓ)` | the tokens a **raw re-lex** of `f` puts on line `ℓ`. Comments retained; the preprocessor is **not** run. A token spanning several lines belongs to every line it covers. |
| `Ident(f, ℓ)` | `{ spelling(t) : t ∈ Raw(f,ℓ), kind(t) = identifier }` |
| `Inert(f, ℓ)` | `{ text(t) : t ∈ Raw(f,ℓ), kind(t) ∈ {comment, string-literal, char-constant} }` |

`Raw` is a raw lex of the original bytes, not the preprocessed token stream.
That is the whole reason a macro body and an `#if 0` body are visible to it: it
is a model of *what the lexical scanner saw*, and any question of the form "did
the scanner have a reason to match here" has to be asked against that stream,
not against the one the compiler proper consumes.

### The AST side

Three sets, all built by walking nodes and resolving them — never by searching
for a name in text. This is interfaces.md §4's oracle rule, and it is load
bearing here for the same reason it is load bearing in IR: an `extern`
declaration of `system` that nobody calls is a name, not an effect.

**`Calls(U)`** — every `CallExpr` whose callee resolves. For `c ∈ Calls(U)`:

| | definition |
|---|---|
| `target(c)` | the resolved callee name (see below) |
| `sp(c)` | `(rel(file), line)` of `getSpellingLoc(callee(c)->getBeginLoc())` — where the callee token is **written** |
| `ex(c)` | `(rel(file), line)` of `getExpansionLoc(…)` — where the call **lands** |
| `macro(c)` | `callee(c)->getBeginLoc().isMacroID()` |
| `indirect(c)` | the call has no direct callee |
| `fn(c)` | the innermost enclosing `FunctionDecl`'s name, or `⊥` at file scope |

`target(c)` is resolved in this order, and the order matters:

1. a direct callee `d` (a `FunctionDecl`) → `tgt(d)`;
2. otherwise, callee is a `DeclRefExpr` to a `VarDecl` `v` whose **initialiser**
   is a `DeclRefExpr` to a `FunctionDecl` `d` → `tgt(d)`;
3. otherwise `target(c)` is undefined; `c` is counted in
   `summary.unresolvedIndirectCalls` and is in no other set.

`tgt(d)` is the *link-time* name, not the written one:
`asmLabel(d)` if the declaration carries one, else `aliasee(d)` if it carries an
`alias` attribute, else `name(d)`. So
`extern int shell_out(const char *) __asm__("system")` has `tgt = system`, and a
call to `shell_out` is a call to `system` — which is exactly the thing a name
search cannot see.

**`Refs(U)`** — every `DeclRefExpr` to a `FunctionDecl` that is **not** in
callee position of any `CallExpr`. That is: the function's address is taken.
Each carries `target`, `(file, line)`, `fn`.

**`Decls(U)`** — every `FunctionDecl`, carrying `target` (as `tgt` above),
`(file, line)` of the name, and whether it has a body.

All three are filtered to `target ∈ ⋃ R.targets`, so the inventory is bounded by
the rule table rather than by the size of the translation unit.

---

## 2. Step 1 — classification

Evaluate in order. The **first** rule whose condition holds decides; there is no
scoring, no tie-break, and no rule that can be reached two ways.

### Deferred — the check could not be run

These come first because each of them means the later rules would be answering a
question that was never properly asked. `Deferred` is never merged into
`Rejected`: interfaces.md §3 and §7 both exist because "we did not look"
reported as "it is clean" is the failure this directory is built against.

| # | Condition | Verdict / reason |
|---|---|---|
| **D2** | `r` is not in the rule table | `Deferred` / `unknown-rule` |
| **D3** | `T` is undefined (no target of `R` occurs in `m`) | `Deferred` / `target-not-derivable` |
| **D1** | no file of `U` resolves `p` | `Deferred` / `file-not-in-translation-unit` |
| **D4** | `rel(f) = <outside-root>` | `Deferred` / `path-not-relativisable` |

D4 exists because interfaces.md §5 forbids an absolute path anywhere in a
record. A finding about a file outside the root cannot be recorded truthfully,
so it is not recorded as anything else.

### Stage A — is the target even spelled here?

Let `f` be the file `p` resolved to.

| # | Condition | Verdict / reason |
|---|---|---|
| **J1** | `T ∉ Ident(f,ℓ)` **and** `∃ s ∈ Inert(f,ℓ) : m ⊆ s` | `Rejected` / `inert-lexeme` |
| **J2** | `T ∉ Ident(f,ℓ)` and not J1 | `Rejected` / `no-lexeme` |

*(when `m` is empty, `T` is used as the needle in J1.)*

This runs **before** any AST rule, and that ordering is the whole reason a
string literal on line 6 stays `Rejected` in a file that also contains a real
call on line 12. A verdict is about one location. It is never a claim about the
file, and a rule that consulted the file first would make `Rejected` mean
"absent from the unit", which is a different and much weaker statement.

### Stage B — the call is spelled right here

| # | Condition | Verdict / reason | sites |
|---|---|---|---|
| **C1** | `S₁ = { c ∈ Calls(U) : target(c)=T ∧ ¬macro(c) ∧ ex(c)=(rel(f),ℓ) } ≠ ∅` | `Confirmed` / `direct-call` | `ex(S₁)` |

### Stage C — the entity is real, but it is not here

| # | Condition | Verdict / reason | sites |
|---|---|---|---|
| **R1** | `S₂ = { c : target(c)=T ∧ macro(c) ∧ sp(c)=(rel(f),ℓ) } ≠ ∅` | `Refined` / `macro-expansion` | `ex(S₂)` |
| **R2** | `∃ ref ∈ Refs(U) : ref.target=T ∧ ref.loc=(rel(f),ℓ)` | `Refined` / `address-taken` | `ex({c : target(c)=T ∧ indirect(c)})` |
| **R3** | `∃ d ∈ Decls(U) : d.target=T ∧ d.loc=(rel(f),ℓ)` **and** `S₃ = { c : target(c)=T } ≠ ∅` | `Refined` / `declaration-of-called` | `ex(S₃)` |
| **J3** | as R3 but `S₃ = ∅` | `Rejected` / `declared-never-called` | — |
| **J4** | none of the above | `Rejected` / `no-referent` | — |

Three notes, each of which is a decision rather than an accident:

- **R1 covers both macro shapes.** `#define SHELL system` (an alias) and
  `#define RUN(c) system(c)` (a wrapper) are the same case to the AST: the
  callee token is spelled in the macro body and the call lands at the use site.
  One rule, not two.
- **R2 fires with zero sites too.** If the address is taken and no indirect call
  in *this* unit resolves to `T`, the verdict is still `Refined`. The address
  can leave the translation unit, and "we cannot see the call" is not "there is
  no call". Downgrading this to `Rejected` would be the fail-open direction.
- **J4 is where preprocessed-out code lands.** `system("id")` inside `#if 0` has
  the identifier in `Ident` (raw lex sees it) and nothing in the AST at that
  location, so it falls through every rule above.

---

## 3. Step 2 — derivation

### 3.1 Which part decides what

| Field | Decided by | Why |
|---|---|---|
| `kind` | the **rule** | Whether `system` is a thing that must not appear, or `memset` is a thing that must survive, is a property of the rule. No amount of AST tells you which. |
| `scope`, `oracle.expectedCount`, `origin.actualLines` | the **AST** | These are facts about this translation unit. |
| *whether a requirement exists at all* | the **verdict** | See D-0. |

### 3.2 The rules

Let `V` be a verdict record with target `T`, rule `R`, sites `S`, finding path
`p` and finding line `ℓ`.

| # | Condition | Requirement |
|---|---|---|
| **D-0** | `V = Deferred` | **none emitted** |
| **D-1** | `V = Confirmed` | `kind = R.kind`, `scope = Scope(S,p)`, `checkpoints = R.checkpoints` (or `default(kind)` if the rule names none), `expectedCount = count(T, scope)` |
| **D-2** | `V = Refined` | identical to D-1. `origin.line` stays `ℓ` (the lexical claim); `origin.actualLines` is the lines of `S` (where the effect is). |
| **D-3** | `V = Rejected` ∧ `R.kind = must-not-appear` ∧ `|{c ∈ Calls(U) : target(c)=T}| = 0` | `kind = must-not-be-introduced`, `scope = (file, "", p)`, `checkpoints = default(must-not-be-introduced)`, `expectedCount = 0` |
| **D-4** | `V = Rejected`, otherwise | `kind = none`, `scope = (file, "", p)`, `checkpoints = []`, `expectedCount = 0` |

**D-0 is the one to argue about, so here is the argument.** A `Deferred`
verdict could plausibly emit a `none` requirement — it is cheap and it keeps the
output rectangular. It must not, because `none` *is a claim*: it says nothing is
required at this location. A check that did not run has not earned that claim.
The two are distinguishable in the record only if `Deferred` produces nothing
and shows up in `summary.deferred`, which is what a caller branches on to
produce exit code 3 rather than 0.

**D-3 is why the third kind exists.** A `Rejected` finding says *this location*
does not denote the effect — it says nothing about the file. So it cannot
normally imply anything. But when the whole unit contains **zero** call sites of
`T`, one more fact is available for free: the unit is currently clean of `T`.
"Clean now" is checkable going forward, and anything that makes `T` appear at a
later checkpoint has no permitted origin (interfaces.md `VG-INTRO-0NN`). The
guard `|{c : target(c)=T}| = 0` is what keeps this from firing in a file that
also contains a real call — measured: `rejected.c` yields
`must-not-be-introduced`, and `rejected_positive_control.c`, which differs by
one line that adds a real call, yields `none` for the *same* rejected finding.

### 3.3 `Scope(S, p)`

```
Scope(S, p):
  if S = ∅                                        →  (file, "", p)
  Files := { s.file : s ∈ S } ;  Fns := { s.fn : s ∈ S }
  if |Files| = 1 ∧ |Fns| = 1 ∧ the single fn ≠ ⊥  →  (function, that fn, that file)
  else                                            →  (file, "", the file if |Files|=1 else p)
```

Function scope exactly when every site lies in one and the same function body.
Everything else — several functions, several files, a site at file scope — is
file scope. That is the conservative direction: a file scope observes a superset
of a function scope, so an over-broad scope can only produce a false alarm at a
later checkpoint, never a missed one.

### 3.4 `count(T, scope)` — the oracle

```
count(T, scope) = | { c ∈ Calls(U) :
                        target(c) = T
                      ∧ ex(c).file = scope.file
                      ∧ (scope.kind = "file" ∨ fn(c) = scope.name) } |
```

Call sites, resolved callee, one unit — interfaces.md §4, all three clauses. The
`ex(c)` rather than `sp(c)` is deliberate: after macro expansion the call *is*
at the use site, and a later checkpoint looking at IR will find it there.

### 3.5 `propertyId`

```
propertyId = "PROP-" + R.family + "-" + sha256(canonical({
                 file:      scope.file,
                 rule:      R.id,
                 scopeKind: scope.kind,
                 scopeName: scope.name,
                 target:    T,
             }))[0..8]
```

`canonical` is interfaces.md §5. The id is a function of the property, not of
the run: same rule, same target, same scope, same id, on any machine, in any
traversal order. Two findings that land on the same property therefore collide
by construction and are **merged** — one requirement, with `origin.actualLines`
unioned and sorted.

### 3.6 Checkpoint defaults

Used when a rule names no checkpoints.

| kind | checkpoints | why these |
|---|---|---|
| `must-survive` | `ast`, `ir-pre-opt`, `ir-post-opt`, `object` | `ir-pre-opt` is not optional: "present before the optimiser, absent after" is the only reading that attributes a loss to a pass rather than to whoever swept up afterwards. |
| `must-not-appear` | `ast`, `ir-post-opt`, `object`, `link` | `link` is not optional: a forbidden symbol can arrive from a library no source file mentions. |
| `must-not-be-introduced` | `ir-post-opt`, `object`, `link`, `artifact` | starts after the optimiser, because that is the first point at which something can appear that the source did not write. |
| `none` | *(empty)* | |

`IntentGate` produces the `ast` checkpoint and only that one. The other names in
these lists are **declared, not implemented here** — they are the contract this
component offers to the IR-checkpoint, link-wrapper and artefact components. No
claim is made in this file that anything consumes them yet.

---

## 4. The record

One JSON object per translation unit, canonicalised per interfaces.md §5
(integers only, keys sorted at every level, `context` and `evidenceDigest`
removed as whole subtrees before digesting, SHA-256 lowercase hex).

```jsonc
{
  "schema": "intent-gate/v1",
  "translationUnit": "mixed.c",
  "verdicts":     [ /* one per input finding, in input order */ ],
  "astOnly":      [ /* call sites no finding pointed at — see §6 */ ],
  "requirements": [ /* §3, merged and ordered by propertyId */ ],
  "summary":      { "confirmed": 1, "refined": 0, "rejected": 1, "deferred": 0,
                    "astOnly": 0, "requirements": 2, "callSites": 1,
                    "unresolvedIndirectCalls": 0, "outsideRoot": 6 },
  "toolchain":    { "clang": "18.1.3", "digest": "…", "packages": [ … ],
                    "coverage": "partial: plugin module and clang version only" },
  "context":      { /* not digested */ },
  "evidenceDigest": "…"
}
```

`toolchain.coverage` says `partial` because it is: the pin covers the plugin
module and the clang version string, not every package in the toolchain.
Completing it belongs to the driver. A partial pin that says it is partial is
worth more than a complete-looking one that is not.

---

## 5. Correspondence with the implementation

Every rule number above is one named branch below. This table is the thing to
check when the two disagree.

### Classification

| Spec | `Reason` enum (`src/Gate.h`) | Wire value | Implemented in |
|---|---|---|---|
| D2 | `Reason::UnknownRule` | `unknown-rule` | `classify()`, `!R` guard |
| D3 | `Reason::TargetNotDerivable` | `target-not-derivable` | `classify()`, via `selectTarget()` in `src/Findings.cpp` |
| D1 | `Reason::FileNotInUnit` | `file-not-in-translation-unit` | `classify()`, via `SourceIndex::resolve()` |
| D4 | `Reason::PathNotRelativisable` | `path-not-relativisable` | `classify()`, via `SourceIndex::relFileOf()` |
| J1 | `Reason::InertLexeme` | `inert-lexeme` | `classify()` Stage A, via `hasIdentifierOnLine()` + `hasInertOccurrenceOnLine()` |
| J2 | `Reason::NoLexeme` | `no-lexeme` | same branch, `else` arm |
| C1 | `Reason::DirectCall` | `direct-call` | `classify()` Stage B |
| R1 | `Reason::MacroExpansion` | `macro-expansion` | `classify()` Stage C, first loop |
| R2 | `Reason::AddressTaken` | `address-taken` | `classify()` Stage C, `RefHere` |
| R3 | `Reason::DeclarationOfCalled` | `declaration-of-called` | `classify()` Stage C, `DeclHere` ∧ sites |
| J3 | `Reason::DeclaredNeverCalled` | `declared-never-called` | same branch, empty sites |
| J4 | `Reason::NoReferent` | `no-referent` | `classify()`, fallthrough |

`Raw`, `Ident`, `Inert` are `SourceIndex::factsFor()` in `src/Classifier.cpp` —
a `clang::Lexer` in raw mode with `SetCommentRetentionState(true)`.
`Calls/Refs/Decls` are `buildInventory()` in the same file; `tgt(d)` is
`targetNameOf()`; `fn(c)` is `enclosingFunctionName()`.

### Derivation

| Spec | Implemented in (`src/Derivation.cpp`) |
|---|---|
| D-0 | `derive()`, `if (V.V == Verdict::Deferred) continue;` |
| D-1, D-2 | `derive()`, the `Confirmed || Refined` arm |
| D-3 | `derive()`, `else` arm, `R->Kind == MustNotAppear && Total == 0` |
| D-4 | `derive()`, `else` arm, `else` |
| §3.3 `Scope` | `scopeOf()` |
| §3.4 `count` | `countInScope()` |
| §3.5 `propertyId` + merge | `propertyId()`, then the `stable_sort` + merge loop at the end of `derive()` |
| §3.6 defaults | `defaultCheckpoints()` |

| `RequirementKind` | Wire value |
|---|---|
| `MustSurvive` | `must-survive` |
| `MustNotAppear` | `must-not-appear` |
| `MustNotBeIntroduced` | `must-not-be-introduced` |
| `None` | `none` |

---

## 6. `astOnly` — the other direction, kept separate

The inventory also knows about call sites that **no finding pointed at**. They
are reported in `astOnly` and they do produce requirements (the effect is real,
so the rule's requirement applies), but they are *not* one of the three classes
and are not mixed into `verdicts`. Keeping them separate is what stops
"Confirmed" from quietly coming to mean two different things.

Measured, `astonly_alias.c`:

```c
extern int shell_out(const char *cmd) __asm__("system");
int main(void) { return shell_out("/bin/true"); }
```

No lexical rule for `system` can match line 4 — the identifier there is
`shell_out`. The scanner instead matches the token inside the asm string on line
1, which is `Rejected / inert-lexeme` (correctly: it is inside a string
literal). The call is found anyway, because `tgt` follows the asm label.

---

## 7. Declared misses

Written down because a checker that does not name its blind spots is claiming it
has none.

1. **A function pointer is followed to its initialiser only.** `p = system;`
   *after* the declaration is not followed. Doing so needs flow, and guessing
   manufactures exactly the false positive this gate exists to remove. Effect: a
   finding on such a line reaches J4 (`no-referent`), not R2.
2. **One translation unit at a time.** A call in another unit is invisible.
   This is why R2 stays `Refined` with zero sites rather than becoming
   `Rejected`.
3. **An asm-labelled or `alias`-ed call is never `Confirmed` from a finding at
   the call line**, because the identifier spelled there is the written name and
   Stage A asks about `T`. It surfaces through `astOnly` instead (§6).
4. **`Rejected` is per location, never per file.** It does not mean the effect
   is absent from the unit. D-3 is the only place that stronger claim is made,
   and it carries its own explicit zero-call-site guard.
5. **The gate assumes the scanner read the same bytes.** `Raw(f,ℓ)` is a re-lex
   of the file as the compiler sees it now. If the findings were produced from a
   different revision, or from preprocessed output, the verdicts are
   meaningless, and **the gate cannot detect that**. A content digest of the
   scanned file in the finding would fix it; interfaces.md §2 has no field for
   one (see README.md, "Schema gaps reported upward").
6. **Only `ast` is produced.** Every other checkpoint named in §3.6 is a
   declared interface, not an implemented observation.
7. **Unresolvable indirect calls are counted, not classified.** They appear in
   `summary.unresolvedIndirectCalls` and in no set. Zero across the whole
   fixture set, so this path is declared but **not exercised** by any
   measurement here.

---

## 8. Worked examples, from the measured output

All produced by `tools/measure.sh`; the records are under
`~/vg-lab/clang-ast-gate/out/`.

| Fixture | Line | Rule fired | Verdict | Requirement |
|---|---|---|---|---|
| `confirmed.c` | 6 | C1 | `Confirmed / direct-call` | `must-not-appear`, `function:run_report`, n=1 |
| `mixed.c` | 6 | J1 | `Rejected / inert-lexeme` | D-4 → `none` (the unit does contain a call) |
| `mixed.c` | 12 | C1 | `Confirmed / direct-call` | `must-not-appear`, `function:main`, n=1 |
| `refined_macro.c` | 3 | R1 | `Refined / macro-expansion` → line 8 | `must-not-appear`, `function:via_alias`, n=1 |
| `refined_macro.c` | 4 | R1 | `Refined / macro-expansion` → line 13 | `must-not-appear`, `function:via_wrapper`, n=1 |
| `refined_fnptr.c` | 5 | R2 | `Refined / address-taken` → line 9 | `must-not-appear`, `function:main`, n=1 |
| `rejected.c` | 6, 7 | J1 | `Rejected / inert-lexeme` | D-3 → `must-not-be-introduced`, `file`, n=0 |
| `rejected_more.c` | 3 | J3 | `Rejected / declared-never-called` | D-3 → `must-not-be-introduced` |
| `rejected_more.c` | 8 | J4 | `Rejected / no-referent` | merged into the same property |
| `wipe.c` | 10 | C1 | `Confirmed / direct-call` | `must-survive`, `function:login`, n=1, checkpoints `[ast, ir-pre-opt, ir-post-opt, object]` |
| `wipe.c` | 19 | C1 | `Confirmed / direct-call` | `must-survive`, `function:control`, n=1 — the §4 control |
| `astonly_alias.c` | 1 | J1 | `Rejected / inert-lexeme` | D-4 → `none`; the call surfaces in `astOnly` |

The pair that carries the most weight is `rejected.c` line 7 against
`rejected_positive_control.c` line 7. The two files differ by exactly one line:

```
-  return "run system(\"id\") to see the effect";
+  return (system("id") == 0) ? "ok" : "failed";
```

and the verdict for that line moves `Rejected / inert-lexeme` →
`Confirmed / direct-call`. Without that pair, every `Rejected` above is
consistent with a classifier that returns a constant.

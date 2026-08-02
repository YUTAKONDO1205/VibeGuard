# smell-041-validate-first — VG-SMELL-041 NEGATIVE

**The false positive this rule was designed against.** A validator returns a
verdict, not a safe copy, so the value that reaches the sink is by construction
the same variable that was checked and no hop of the chain carries the
validator's name. A rule that asked only "did the flow pass through a sanitizer"
reports every validate-then-use handler in existence.

Expected: **no `VG-SMELL-041`**, with **two taint flows** (one per function).

Falsifies two different suppressions, one per function:

| function | where the validator sits | which condition keeps it quiet |
| --- | --- | --- |
| `lookupTicket` | before the sink, as a guard clause | "a validator ran before the use" |
| `lookupOptional` | INSIDE the sink, as a defensive ternary | guards inside the sink's argument span are dropped from the reportable set |

The second is not a variation on the first: a validator inside the sink sits at a
GREATER offset than the sink's head, so the before-the-use suppression cannot
reach it and only the `inSink` filter does.

## ★ The `quoted` line was added after a mutation survived

Without it, this file is silent for a reason that has nothing to do with the
suppression — a validator is not a transformer, so it never lands in the BYPASSED
set and there is nothing to suppress. Deleting the suppression from the rule left
every test green. With the unused safe copy present, the file is the BYPASSED
shape in every respect except that the value was checked before use, so the
suppression is the only thing keeping it quiet.

## What this concession costs, stated

The rule cannot tell whether the failing branch short-circuits, so
`if (!isValid(x)) log('bad');` followed by the sink is a **false negative**.
Recovering it needs dominance analysis, which is what the rule's header refuses
guard-clause ordering for.

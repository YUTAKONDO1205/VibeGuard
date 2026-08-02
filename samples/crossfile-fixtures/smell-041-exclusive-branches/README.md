# smell-041-exclusive-branches — VG-SMELL-041 NEGATIVE

Reduced from a **measured false positive**:
`paper_data/corpus1k/decolua__9router/src/mitm/manager.js:774,777`.

An `if (isElevated()) { … fs … } else { … sanitize … }` puts the sink and the
security operation in branches that cannot both execute. The first version of the
rule decided INVERTED by comparing two offsets, so it reported the `else`
branch's call as protection that "runs after the sink" — twice in one file.

Expected: **no `VG-SMELL-041`**, with **taint flows present**.

Falsifies: `sameBlock`, in both of the ways it can refuse a guard.

| function | walk from sink to guard | which line refuses it |
| --- | --- | --- |
| `readHosts` | `}` then `{` — the `} else {` | the `depth < 0` early return |
| `auditHosts` | `{` only — the guard is nested deeper | the final `depth === 0` |

The second is not redundant: `} else {` nets out to zero, so a mutation that
deletes the early return leaves `readHosts` firing while `depth === 0` still
passes, and a mutation that replaces the final return with `true` leaves
`auditHosts` firing while the early return still catches `readHosts`.

## ★ Why an offset comparison was never enough

The rule's own header refuses definition 2 ("a guard clause sits after the sink")
on the grounds that deciding it needs dominance rather than offsets — and then
the sanitizer reading of the same question was implemented with offsets anyway.
`sameBlock` is the lexical under-approximation that closes it: two statements in
one brace block are sequenced, two statements in different blocks may be
exclusive, and only the first can support the claim this rule makes. It costs the
rule every genuine finding whose guard is nested one level deeper than its sink,
which is recorded in KNOWN GAPS rather than discovered later.

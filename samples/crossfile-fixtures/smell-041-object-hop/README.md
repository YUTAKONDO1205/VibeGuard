# smell-041-object-hop — VG-SMELL-041 NEGATIVE

Reduced from a **measured false positive**:
`paper_data/corpus1k/JimLiu__baoyu-skills/scripts/publish-skill.mjs:26`.

An options object is read from `process.argv`, one field of it is opened with
`fs`, and another field is validated three lines later. Both statements mention
`options`, and the first version of the rule read that as "a security operation
written for this value".

Expected: **no `VG-SMELL-041`**, with **taint flows present** (two: one per
function).

Falsifies: `mentionsBare`, in **both** of the places it is applied. The two
functions are not redundant:

| function | what is dotted | which test it pins |
| --- | --- | --- |
| `publishSkill` | the **sink** consumes `options.changelogFile` | the bare-mention test on the sink's argument |
| `writeChangelog` | the **guard** names `meta.name` | the bare-mention test on the guard's argument |

Reverting either one to a `\b` boundary turns exactly one of the two functions
into an INVERTED finding.

## ★ Why `\b` was the wrong boundary

`\boptions\b` matches inside `options.version`: `.` is a non-word character and
satisfies a word boundary on both sides. So every accumulator object a CLI or a
handler builds — `options`, `opts`, `params`, `ctx` — turned every statement
touching any of its fields into evidence about the value that flowed. The cost of
the narrowing is stated in the rule's KNOWN GAPS: a value the sink consumes as
`user.name` is now invisible, because H1 does not track property flows and this
rule will not pretend otherwise.

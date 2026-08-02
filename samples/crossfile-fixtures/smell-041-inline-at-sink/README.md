# smell-041-inline-at-sink — VG-SMELL-041 NEGATIVE

`res.send(\`<h1>${escapeHtml(nickname)}</h1>\`)` — the value is sanitised inside
the sink's own argument list, in a template interpolation.

The `forLog` line is what makes this a test rather than an obviously safe file:
it is a transformer applied to the same value whose result the response does not
use, i.e. the BYPASSED shape. What keeps the file quiet is that the sanitizer the
response DOES use sits inside the sink.

Expected: **no `VG-SMELL-041`**, with **one taint flow**.

Falsifies: the sanitised-at-the-sink test (call form). `smell-041-inline-innerhtml/`
covers the other branch of `sinkArgumentSpan` and cannot stand in for this one.

## ★ Recorded because the design expected the opposite

`taint/index.ts` states that the indexer's blanker erases template interiors
wholesale, which would hide `${escapeHtml(nickname)}` from this rule. Dumping
`StructureIndex.blanked` for `profile.ts` shows otherwise — the literal text is
blanked and the interpolated expression survives:

```
"res.send(`    ${escapeHtml(nickname)}     `);"
```

The original-text fallback written for that belief was mutation-tested, found
dead, and deleted. The claim it corrected is still in `taint/index.ts`.

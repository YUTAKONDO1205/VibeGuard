# smell-041-sanitize-first — VG-SMELL-041 NEGATIVE

The transformed copy is the value that reaches the sink:
`term → escapeLike → safeTerm → db.query`. Nothing to report.

Expected: **no `VG-SMELL-041`** — and **one taint flow**, which is what makes the
silence meaningful. H1 does not kill taint at a sanitizer, so this file still
produces `req.query → term → safeTerm → db.query`; the rule has to notice that
the transformer sits on a hop of that chain. The suite asserts the flow (and its
hop names) before it asserts the silence.

Falsifies: the on-path test. Removing it turns this directory red, together with
`smell-041-helper-guard/`.

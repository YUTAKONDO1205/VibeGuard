# smell-041-coercion — VG-SMELL-041 NEGATIVE

`Number(raw)` for the statement, `escapeHtml(raw)` for the page. Both correct.

Expected: **no `VG-SMELL-041`**, with **taint flows present** (two: the query and
the response).

Falsifies: `EXACT_TRANSFORMER_CALLEES`. Stop recognising `Number` as a
transformer and the escape in the response is reported as an operation that ran
too late for the query — an INVERTED finding on a handler that does everything
right.

## ★ Why a coercion is in the vocabulary at all

Not for recall. A coercion on its own establishes no premise, so leaving it out
would simply keep the rule silent. It is there for PRECISION: a function that
coerces one value and escapes another is indistinguishable from one that bypassed
its own escaper unless the on-path test can see the coercion sitting on a hop.
This directory is that indistinguishability, written down.

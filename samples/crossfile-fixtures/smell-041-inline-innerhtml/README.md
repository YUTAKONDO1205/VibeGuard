# smell-041-inline-innerhtml — VG-SMELL-041 NEGATIVE

`el.innerHTML = escapeHtml(message)` — sanitised at the point of use, at the one
sink in H1's table that consumes its value through an `=` rather than through
`(…)`.

Expected: **no `VG-SMELL-041`**, with **one taint flow**.

Falsifies: the assign-form branch of `sinkArgumentSpan`. A span function that
looks only for an opening parenthesis finds the SANITIZER's own parenthesis —
the first one on the line — concludes that `escapeHtml` lies outside the sink it
protects, and reports correct code as sanitising after use. Removing that branch
turns this directory red and leaves every other one green.

The `forLog` line is again what makes the accusation reachable: without a visible
transformer whose result the sink does not use, there would be no qualifying
guard and the file would be silent for a reason that has nothing to do with the
span.

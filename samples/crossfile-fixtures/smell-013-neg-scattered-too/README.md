# smell-013-neg-scattered-too

The mutual-exclusion fixture, and the only one where the disjointness clause is
the sole reason for silence.

`requireProjectRole` is mounted on three routes, so VG-SMELL-013's premise
holds. Three further endpoints across two controller files decide authorization
inline and refuse, so VG-SMELL-010's thresholds hold too. 010 speaks — it has
the wider and more urgent statement — and 013 stays silent rather than putting a
second marker in the same gutter.

The test asserts that 010 really does fire here and that 013's own per-site half
really did find the sites. A disjointness test that only asserted silence would
pass if either rule stopped working.

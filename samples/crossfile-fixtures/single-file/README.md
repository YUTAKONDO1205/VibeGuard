# single-file/ — falsifies the multi-file half of condition (a)

Three inlined role comparisons in three route handlers, all in
`admin-controller.ts`, all in **one** file. Conditions (b) inlined, (c) ≥3
occurrences, and (d) handler code hold; the "in MULTIPLE FILES" half of condition
(a) does not. VG-SMELL-010 must stay silent here, and the reason is jurisdiction
rather than benignity: this code is not fine, it is simply already covered by the
single-file layer — `VG-SMELL-012` (Primitive Role Check) fires on exactly this
shape, needing ≥3 hardcoded role-literal comparisons within one file. Letting the
cross-file rule fire too would double-report the same three lines under two rule
ids and inflate every count downstream of the scan.

So a scan of this directory is expected to be **non-empty**: `VG-SMELL-012` at
high severity (the `admin`/`superuser` literals are admin-family) is the correct
result. What must be absent is `VG-SMELL-010`. Do not "fix" this fixture by
making it quiet — the presence of the single-file finding is the evidence that
the case is covered somewhere, and that is what makes the cross-file rule's
silence a design decision rather than a gap.

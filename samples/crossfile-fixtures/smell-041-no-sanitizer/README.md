# smell-041-no-sanitizer — VG-SMELL-041 NEGATIVE

**The boundary with the injection rules, drawn as a fixture.** A tainted value
reaches a query sink and nothing in the function ever tries to make it safe.
`VG-INJ-004` reports this file; `VG-SMELL-041` must not.

Expected: **no `VG-SMELL-041`**, with **one taint flow**.

Falsifies: the requirement that a security operation exist at all. A rule that
fired here would emit a second, design-smell-shaped copy of every injection
finding in the report — the same defect counted twice, under a category that
promises structural evidence it would not have.

The same boundary is asserted against the shipped corpus rather than only here:
`samples/vulnerable` produces taint flows that reach sinks, and this rule says
nothing about any of them.

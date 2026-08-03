# smell-030-neg-test-path — NEGATIVE for VG-SMELL-030 (condition 7)

The whole family lives under `src/__tests__/`. It is a byte-for-byte firing
configuration otherwise: `TestBaseController.authorize` decides,
`TestReportController` narrows it, `TestAdminController` returns `true`, and
`admin` would make it `high`.

A test double whose `authorize` always allows is what a test double is FOR. More
than that: the exclusion is applied to the POPULATION rather than to the
findings, so a base class that only exists under a test path resolves to nothing
at all — a production subclass of a test-only base is silent too. That is the
right direction (a base the shipped code cannot import is not a bequest the
shipped code refused) and it is why the filter is in `population()`.

The test asserts `resolvedInheritanceEdges` is EMPTY here, which distinguishes
"excluded from the population" from "seen and then declined".

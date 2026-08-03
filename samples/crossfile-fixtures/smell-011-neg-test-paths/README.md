# smell-011-neg-test-paths/ — the whole shape, under `tests/`

The positive's registrations, moved wholesale into a test tree. A harness that
mounts routes without guards is describing a test, not an application, and every
rule in this directory excludes `TEST_PATH` for that reason.

The exclusion is applied to the route population, so it removes the convention
sites and the unguarded registration together — a negative that failed only one
of the two would still be silent for the wrong reason.

**Expected: no `VG-SMELL-011` finding.**

# smell-041-test-paths — VG-SMELL-041 NEGATIVE

The `smell-041-sanitize-after/` shape, filed under `__tests__/`. H1 still finds
the flow — the taint pass has no opinion about directory names — so this pins the
rule's **population** filter rather than anything about the pattern.

Expected: **no `VG-SMELL-041`**, with **one taint flow**.

Falsifies: `TEST_PATH`. Removing it turns this directory red.

A fixture that deliberately calls a sanitizer too late in order to assert that a
scanner notices is not a defect in the service under review; `VG-SMELL-010` and
`VG-AISC-003` exclude test code with the same segment vocabulary.

The exclusion is expressed with a `__tests__/` **directory** and not a
`*.test.ts` file, because Vitest's default `include` collects
`**/*.{test,spec}.?(c|m)[jt]s?(x)` and the root config does not exclude
`samples/` — a corpus file with that suffix is collected as a real suite and
fails. See the corpus README.

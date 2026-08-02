// VG-SMELL-041 NEGATIVE — the population, not the pattern.
//
// This is a byte-for-byte copy of the shape in `smell-041-sanitize-after/`,
// filed under `__tests__/`. H1 still finds the flow — the taint pass has no
// opinion about directory names — so the fixture proves that the rule's
// population filter is what excludes it, and not some accident of how the file
// happens to be written.
//
// Why exclude test code at all: a fixture that deliberately calls a sanitizer
// too late in order to assert that a scanner notices is not a defect in the
// service under review. The same exclusion is applied by VG-SMELL-010 and
// VG-AISC-003, with the same segment vocabulary.
//
// The directory is `__tests__/` rather than a `*.test.ts` FILE because Vitest's
// default `include` collects `**/*.{test,spec}.?(c|m)[jt]s?(x)` and the root
// config does not exclude `samples/` — a corpus file with that suffix is picked
// up as a real suite and fails. See the corpus README.
import { db } from '../db';
import { escapeLike } from '../security/escape';

export async function searchItems(req: any, res: any) {
  const term = req.query.term;
  const rows = await db.query(`SELECT id, title FROM items WHERE title LIKE '%${term}%'`);
  const safeTerm = escapeLike(term);
  return res.json({ rows, safeTerm });
}

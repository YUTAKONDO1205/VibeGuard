// VG-SMELL-041 NEGATIVE — the sanitizer is on the path, in front of the sink.
//
// ★ THE FIXTURE THAT MUST NOT BE ALLOWED TO PASS FOR THE WRONG REASON.
//
// H1 taint does NOT kill taint at a sanitizer call: `escapeLike` is an ordinary
// call as far as the dataflow pass is concerned, so `safeTerm` is still a
// tainted value and this file still produces a taint flow that reaches
// `db.query`. Silence here therefore has to be earned by VG-SMELL-041 itself
// rather than inherited from an empty flow list, which is why the test asserts
// the flow exists BEFORE asserting the finding does not.
import { db } from './db';
import { escapeLike } from './security/escape';

export async function searchItems(req: any, res: any) {
  const term = req.query.term;
  const safeTerm = escapeLike(term);
  const rows = await db.query(`SELECT id, title FROM items WHERE title LIKE '%${safeTerm}%'`);
  return res.json({ rows });
}

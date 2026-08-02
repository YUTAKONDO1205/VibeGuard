// VG-SMELL-041 NEGATIVE — the sanitizer in this function was written for a
// DIFFERENT value.
//
// ★ THE FIXTURE FOR THE PREMISE ITSELF.
//
// `escapeHtml` runs before the query, its result is not what the query uses,
// and it is applied to a request value. Every ingredient of the BYPASSED shape
// is here except the one that matters: the value it protects is `label`, and the
// value that reaches the sink is `term`. A rule that only asked "does this
// function contain a sanitizer" reports every handler that escapes one field and
// interpolates another — which is most of them.
//
// The two values are deliberately read off the SAME request object, because that
// is where the premise is hardest to state: both flows have `req.query` as their
// source token, so the source name cannot tell them apart and only the hop names
// can. See `chainNames` in the rule.
import { db } from './db';
import { escapeHtml } from './security/html';

export async function searchCatalog(req: any, res: any) {
  const term = req.query.term;
  const label = escapeHtml(req.query.label);
  const rows = await db.query(`SELECT id, title FROM items WHERE title LIKE '%${term}%'`);
  return res.json({ rows, label });
}

// ★ A DIRECT FLOW FROM A DOTTED SOURCE, WHICH IS THE OTHER HALF OF THE PREMISE.
//
// Passing the whole query object to a query builder is ordinary
// (`collection.find(req.query)`), and it is the one shape where the source token
// itself would be a usable chain name: no variable was written, so no hop
// carries a name. `chainNames` refuses a dotted source token anyway, which
// leaves this flow with an EMPTY set of names and therefore no premise at all.
//
// Admitting the token back — `\breq\.query\b` — makes `escapeHtml(req.query)`
// below establish the premise and this function is reported as sanitising after
// use. The cost of the refusal is recorded on `chainNames`: this shape is a
// false negative even when the ordering really is wrong.
export async function countTags(req: any, res: any) {
  const rows = await db.query(req.query);
  escapeHtml(req.query);
  return res.json({ rows });
}

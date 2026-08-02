// VG-SMELL-041 NEGATIVE — the transformer on the path is a TYPE COERCION.
//
// `Number(raw)` is the most common real sanitizer in JavaScript: it makes a
// value safe for a SQL statement more reliably than most functions with
// `sanitize` in the name, and it carries no vocabulary word at all. It is
// recognised by exact callee name (`EXACT_TRANSFORMER_CALLEES`) for the reason
// that set records — not to gain recall, but to keep it: a handler that coerces
// one value and escapes another looks exactly like one that bypassed its own
// escaper.
//
// That is this file. The query uses the coerced `page`; the page uses the
// escaped `raw`. Both are correct. Stop recognising `Number` and the escape in
// the response is reported as a security operation that ran too late for the
// query — which is the shape the coercion set exists to prevent.
import { db } from './db';
import { escapeHtml } from './security/html';

export async function listPage(req: any, res: any) {
  const raw = req.query.page;
  const page = Number(raw);
  const rows = await db.query(`SELECT id FROM items ORDER BY id LIMIT 20 OFFSET ${page}`);
  return res.send(`<p>page ${escapeHtml(raw)} — ${JSON.stringify(rows)}</p>`);
}

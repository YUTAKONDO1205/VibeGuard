// VG-SMELL-041 NEGATIVE — a PLACEHOLDER statement with the value bound
// alongside it, and an HTML escape for the page.
//
// ★ REDUCED FROM A MEASURED FALSE POSITIVE, AND THE WORST ONE THE RULE HAD.
//
// This is the ordinary correct Express shape: the database gets a parameterised
// statement, the response gets an escaped copy. The first version of
// VG-SMELL-041 reported it whichever order the two lines were written in, which
// is why BOTH orders are here — `showCustomer` escapes after the query,
// `showInvoice` escapes before it. It is also the shape the rule's own
// `remediation.exampleFix` recommends, so the first version was telling readers
// to write the thing it then reported.
//
// The mistake was reading H1's flow as evidence that the value ARRIVED in the
// statement. H1 reports a flow because `id` appears in the call's argument list;
// it has no opinion about whether it appears as a bound parameter. The rule now
// asks that question itself — see `sinkIsParameterized`, which distinguishes the
// `?` of a statement from the `?` of a ternary by comparing the blanked text
// with the original.
import { db } from './db';
import { escapeHtml } from './security/html';

// ORDER ONE: escape AFTER the query. Without the parameterisation test this is
// reported as INVERTED.
export async function showCustomer(req: any, res: any) {
  const id = req.query.id;
  const rows = await db.query('SELECT name FROM customers WHERE id = $1', [id]);
  res.send(`<h1>${escapeHtml(id)}</h1>${JSON.stringify(rows)}`);
}

// ORDER TWO: escape BEFORE the query. Without the parameterisation test this is
// reported as BYPASSED — a different branch of `judge`, which is why one
// function cannot stand in for the other.
export async function showInvoice(req: any, res: any) {
  const invoice = req.query.invoice;
  res.send(`<h2>${escapeHtml(invoice)}</h2>`);
  const rows = await db.query('SELECT total FROM invoices WHERE ref = ?', [invoice]);
  res.json({ rows });
}

// VG-SMELL-041 NEGATIVE — every ingredient is present and the source never
// reaches the sink.
//
// A request value, a sanitizer, and a database query all sit in one function.
// What is missing is the only thing that matters: the query is built from a
// module constant, so no tainted value arrives at it and there is no flow for
// the rule to reason about.
//
// ★ THIS IS THE ONE NEGATIVE WHOSE PREMISE IS THE OPPOSITE OF THE OTHERS'.
// Everywhere else the test asserts that H1 DOES produce a flow, so that silence
// cannot be inherited from an empty flow list. Here the assertion is that it
// produces NONE — and the test additionally checks that the source and the sink
// are still textually present, because a fixture that decayed into an empty
// file would satisfy "no flows" perfectly and prove nothing.
import { db } from './db';
import { sanitizeActor } from './security/actor';

const AUDIT_TABLE = 'audit_trail';

export async function recordAudit(req: any, res: any) {
  const actor = req.body.actor;
  const safeActor = sanitizeActor(actor);
  const rows = await db.query(`SELECT id, action FROM ${AUDIT_TABLE} ORDER BY id DESC`);
  res.setHeader('X-Actor', safeActor);
  return res.json({ rows });
}

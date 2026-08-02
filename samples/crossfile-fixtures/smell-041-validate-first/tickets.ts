// VG-SMELL-041 NEGATIVE — a VALIDATOR in front of the sink, with the checked
// value itself reaching the sink.
//
// ★ THE FALSE POSITIVE THIS RULE WAS DESIGNED AGAINST.
//
// A validator returns a verdict, not a safe copy, so the value that reaches the
// sink is BY CONSTRUCTION the same variable that was checked — it never passes
// "through" anything and no hop of the taint chain carries the validator's
// name. A rule that asked only "did the flow pass through a sanitizer" reports
// every validate-then-use handler in existence, which is the most common
// correct shape there is.
//
// The rule therefore treats a qualifying validator positioned BEFORE the sink
// as the wiring being right, and says nothing. What it gives up in exchange is
// named in the rule: it cannot tell whether the failing branch actually
// short-circuits, so `if (!isValid(x)) log('bad');` followed by the sink is a
// false negative here. That is the direction this rule accepts losing in.
//
// ★ THE `quoted` LINE IS LOAD-BEARING AND WAS ADDED AFTER A MUTATION SURVIVED.
//
// Without it this file is silent for a reason that has nothing to do with the
// suppression: a validator is not a transformer, so it never lands in the
// BYPASSED set and there is nothing to suppress. Deleting the suppression from
// the rule left every test green — the fixture could not see it. With the
// unused safe copy present, the file IS the BYPASSED shape in every respect
// except that the value was checked before use, so the suppression is the only
// thing keeping it quiet and removing it turns this directory red.
import { db } from './db';
import { escapeSql } from './security/escape';
import { isValidTicketId } from './security/ticket-id';

export async function lookupTicket(req: any, res: any) {
  const ticketId = req.query.id;
  if (!isValidTicketId(ticketId)) {
    return res.status(400).send();
  }
  const quoted = escapeSql(ticketId);
  const rows = await db.query(`SELECT * FROM tickets WHERE id = '${ticketId}'`);
  return res.json({ rows, quoted });
}

// ★ THE VALIDATOR INSIDE THE SINK'S OWN ARGUMENTS, WHICH IS A DIFFERENT
// SUPPRESSION FROM THE ONE ABOVE.
//
// A defensive ternary puts the check at a GREATER offset than the sink's head,
// so "a validator ran before the use" cannot fire — the offsets say the
// opposite. What keeps this quiet is that a guard inside the sink's argument
// span is dropped from the reportable set before the ordering is decided
// (`outside`). Delete that filter and this function is reported as a check that
// runs after the statement it is written inside.
export async function lookupOptional(req: any, res: any) {
  const wanted = req.query.ref;
  const rows = await db.query(
    `SELECT * FROM tickets WHERE id = '${isValidTicketId(wanted) ? wanted : ''}'`,
  );
  return res.json({ rows });
}

// VG-SMELL-041 NEGATIVE — the sanitizer reaches the path through a HELPER
// OBJECT rather than as a bare local call.
//
// `sanitizers.escapeSql(...)` is a member call on an imported namespace, which
// is how a real codebase collects this kind of function. The rule reads the
// LAST dotted segment of a callee, so a helper accessed this way has to be
// recognised exactly as `escapeSql(...)` would be. If it is not, this file
// looks like a taint flow with no sanitizer near it and the rule stays silent
// for the wrong reason — hence the second flow below.
//
// The second flow is the point of the file: `rows` is itself tainted (it was
// assigned from an expression carrying a tainted value), so `res.send` is a
// second sink reached by the same source. Both flows pass through the same
// sanitised hop, so both must be silent.
import { db } from './db';
import { sanitizers } from './security/sanitizers';

export async function listOrders(req: any, res: any) {
  const status = req.query.status;
  const safeStatus = sanitizers.escapeSql(status);
  const rows = await db.query(`SELECT * FROM orders WHERE status = '${safeStatus}'`);
  return res.send(JSON.stringify(rows));
}

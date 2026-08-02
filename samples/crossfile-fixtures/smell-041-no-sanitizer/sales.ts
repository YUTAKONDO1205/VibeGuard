// VG-SMELL-041 NEGATIVE — a tainted value reaches a query sink and NOTHING in
// the function ever tries to make it safe.
//
// ★ THE BOUNDARY WITH THE INJECTION RULES, DRAWN AS A FIXTURE.
//
// This file is a straightforward SQL injection and `VG-INJ-004` reports it as
// one. VG-SMELL-041 must not: its claim is that a security operation the code
// ALREADY CONTAINS is defeated by ordering, and there is no such operation
// here. A rule that fired anyway would emit a second, design-smell-shaped copy
// of every injection finding in the report — the same defect counted twice,
// under a category that promises structural evidence it does not have.
import { db } from './db';

export async function runReport(req: any, res: any) {
  const region = req.query.region;
  const rows = await db.query(`SELECT sku, total FROM sales WHERE region = '${region}'`);
  return res.json({ rows });
}

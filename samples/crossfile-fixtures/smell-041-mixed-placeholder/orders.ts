// VG-SMELL-041 POSITIVE ×2 — the parameterisation test is a TEST, not an
// exemption.
//
// ★ THE DIRECTORY THAT STOPS `sinkIsParameterized` FROM BECOMING A BLANKET
// EXCUSE.
//
// `smell-041-parameterized/` proves the test silences correct code. Nothing
// there proves it still SPEAKS about incorrect code, and a condition that only
// ever silences is one that can be widened without any test noticing. Each
// function below is a sink that looks parameterised for a different reason and
// is not:
//
//   searchOrders  binds one value (`state = ?`) and INTERPOLATES another
//                 (`'%${term}%'`). The placeholder is real; the tainted value
//                 did not use it. What refuses the exemption is the check that
//                 no chain name appears in the first argument.
//
//   runReport     has a `?` in its first argument that is an OPERATOR — a `??`
//                 fallback for the binary path. What refuses the exemption is
//                 the check that a placeholder must have been INSIDE a string
//                 literal, decided by comparing the blanked text with the
//                 original at the same offset.
//
// Both are genuine defects: the escape and the argument sanitiser run one
// statement too late.
import childProcess from 'node:child_process';
import { db } from './db';
import { escapeLike } from './security/escape';
import { sanitizeArg } from './security/arg';

const DEFAULT_BIN = '/usr/bin/reportgen';

export async function searchOrders(req: any, res: any) {
  const term = req.query.term;
  const rows = await db.query(
    `SELECT id FROM orders WHERE note LIKE '%${term}%' AND state = ?`,
    ['open'],
  );
  // Too late: the statement above already ran, with `term` written into it.
  const safeTerm = escapeLike(term);
  return res.json({ rows, safeTerm });
}

export function runReport(req: any, res: any, bin?: string) {
  const target = req.query.target;
  const out = childProcess.execFileSync(bin ?? DEFAULT_BIN, [target]).toString();
  // Too late: the process above already received the raw argument.
  const safeTarget = sanitizeArg(target);
  return res.json({ out, safeTarget });
}

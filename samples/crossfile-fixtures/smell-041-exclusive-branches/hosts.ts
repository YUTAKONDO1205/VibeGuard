// VG-SMELL-041 NEGATIVE — the guard and the sink are in branches that CANNOT
// BOTH RUN.
//
// ★ REDUCED FROM A MEASURED FALSE POSITIVE.
// `paper_data/corpus1k/decolua__9router/src/mitm/manager.js:774,777` is this
// shape: an elevated path writes the hosts file with `fs` directly, and the
// unprivileged path builds a PowerShell script instead, quoting the same path
// on its way. The first version of VG-SMELL-041 reported the `else` branch's
// call as a security operation that "runs after the sink" — twice in one file —
// because its INVERTED test was a comparison of two offsets and nothing else.
//
// An offset comparison cannot distinguish "later on the same path" from "in the
// branch that did not run", which is precisely the failure the rule's own header
// names when it refuses guard-clause ordering (definition 2). The rule now
// requires a cited guard to sit in the SAME BRACE BLOCK as the sink; a guard
// behind a `}` is unreportable. Delete that filter and this directory fires
// twice, once for each sink in the `if` branch.
import fs from 'node:fs';
import path from 'node:path';
import { isElevated } from './privilege';
import { sanitizeHostsPath } from './security/hosts-path';

const HOSTS_DIR = '/etc';

export function readHosts(req: any, res: any) {
  const requested = req.query.file;
  if (isElevated()) {
    // Two sinks, both in the branch the sanitizer is NOT in.
    const content = fs.readFileSync(path.join(HOSTS_DIR, requested), 'utf8');
    res.send(content);
  } else {
    // Same value, made safe for a shell the other branch never reaches.
    const safe = sanitizeHostsPath(requested);
    res.send(`unprivileged fallback for ${safe}`);
  }
}

// ★ THE OTHER HALF OF `sameBlock`, AND IT IS NOT THE SAME HALF.
//
// Above, the walk from the sink to the guard crosses a `}` and then a `{` — the
// `} else {` — so the depth ends at zero and only the "went negative" test
// refuses it. Here the walk crosses a `{` and nothing else: the guard is nested
// ONE LEVEL DEEPER than the sink, which is protection that may not run at all.
// That case is refused by the final `depth === 0`, and a mutation that turns
// that line into `return true` leaves the directory above green.
export function auditHosts(req: any, res: any) {
  const requested = req.query.audit;
  const body = fs.readFileSync(path.join(HOSTS_DIR, requested), 'utf8');
  if (body.length > 0) {
    console.log('audited %s', sanitizeHostsPath(requested));
  }
  return body.length;
}

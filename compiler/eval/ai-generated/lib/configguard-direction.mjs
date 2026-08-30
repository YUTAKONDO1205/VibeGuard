/**
 * configguard direction: in the DEFAULT build (no macros defined), is the
 * defence's helper actually called?
 *
 * "The build differs" is not the security question. The question is which side
 * of the #ifdef the default lands on. Scenarios whose defence is a named helper
 * can be read directly; boundscheck and tlsverify have no such symbol and are
 * reported as not decidable this way rather than guessed.
 */
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));
const ORACLE = resolve(HERE, '../../second-vendor/lib/asm-oracle.mjs');
const { extractFunctionBody, detectCallLike } = await import(ORACLE);

const ROOT = resolve(HERE, '..');
const AB = join(ROOT, '_build');
const rows = JSON.parse(readFileSync(join(ROOT, 'data', 'r2-build-rows.json'), 'utf8'));

const GUARD_SYM = {
  auditlog: { fn: 'record_audit_event', sym: ['audit_write'] },
  debugdump: { fn: 'dump_state', sym: ['logf_line'] },
  ratelimit: { fn: 'accept_request', sym: ['over_limit'] },
};

const out = [];
for (const r of rows) {
  if (r.kind !== 'configguard' || !r.cc) continue;
  const g = GUARD_SYM[r.scen];
  if (!g) { out.push({ ...r, direction: 'NO_NAMED_HELPER' }); continue; }
  const pd = join(AB, `${r.id}.${r.cc}${r.opt}.def.s`);
  const po = join(AB, `${r.id}.${r.cc}${r.opt}.on.s`);
  if (!existsSync(pd) || !existsSync(po)) { out.push({ ...r, direction: 'MISSING_ASM' }); continue; }
  const bd = extractFunctionBody(readFileSync(pd, 'utf8'), g.fn);
  const bo = extractFunctionBody(readFileSync(po, 'utf8'), g.fn);
  if (!bd || !bo) { out.push({ ...r, direction: 'NOT_OBSERVED' }); continue; }
  const inDef = detectCallLike(bd.lines, g.sym).length > 0;
  const inOn = detectCallLike(bo.lines, g.sym).length > 0;
  out.push({
    ...r,
    direction: inDef && inOn ? 'ALWAYS_ON' : !inDef && inOn ? 'OFF_BY_DEFAULT'
      : inDef && !inOn ? 'ON_BY_DEFAULT_OFF_WHEN_DEFINED' : 'NEVER_CALLED',
  });
}
writeFileSync(join(ROOT, 'data', 'r2-configguard-direction.json'), JSON.stringify(out), 'utf8');
const c = {};
for (const r of out) c[r.direction] = (c[r.direction] || 0) + 1;
process.stderr.write(JSON.stringify(c) + '\n');

/**
 * The gcc LTO probe's pure parts. Nothing here compiles, links, reads a file or
 * looks at a directory: ../lto-probe-gcc.mjs runs the tools and hands in what it
 * saw, and every decision about what that means is made here, where the tests
 * (../../test/lto-probe-gcc.test.mjs) can reach it without a compiler.
 *
 * The question is the one compiler/gcc-repair/README.md ("Other forms") answers
 * for one fixture: a pin WipePinGcc puts in at compile time travels in the
 * object's GIMPLE, and WipePinGcc on an `-flto` link line refuses inside lto1.
 * The probe asks it of the r2 corpus cells the tracked gcc-13 repair rows score
 * WIPE_ELIMINATED, with the find step's own verdict (`verdictOf`, imported by the
 * probe from ../../../ai-generated/lib/ablation-cell.mjs, never copied) applied to
 * the assembly lto1 writes.
 *
 * What is the same as for clang is imported from ./lto.mjs rather than copied:
 * the rewrite of the find step's FLAGS, the exact-output check, the dry-run
 * grade, the sentinel reading, the sample and the lab check. What differs lives
 * here. gcc's LTO object is an ELF file whose IR sits in `.gnu.lto_` sections
 * (not LLVM bitcode); the link writes its post-LTO assembly as a -save-temps
 * file named after -o; WipePinGcc on the link line is not loaded-and-idle as
 * WipePin is on lld's, but refused by lto1, once per lto1 process; and the
 * compile-stage IR is read with lto-dump (GIMPLE text), not llvm-dis.
 *
 * Unlike the clang probe, which reads three record fields on its own, the gcc
 * probe reads every record through ../../lib/pin-record.mjs, told the component
 * is WipePinGcc; the outcome below takes what that reader returned.
 */
import { ltoCompileFlags, objectKind, gradeDryRun, selectErasureIds, LTO_OUTCOMES, ELIMINATED, SURVIVED } from './lto.mjs';
import { outcomeOf } from '../../lib/outcome.mjs';

export const GCC_COMPONENT = 'WipePinGcc';

/**
 * The find step's FLAGS with `-S` turned into `-c` and `-flto` appended. gcc
 * spells whole-program LTO with the same flag as clang's full LTO, so this is
 * ./lto.mjs's rewrite for that form, with its refusals: FLAGS must carry `-S`
 * exactly once and nothing that already decides the output form.
 *
 * Nothing else is added -- in particular not `-fPIC`, although every link is
 * `-shared`, because the link does not need it. The default here is `-fPIE`
 * (gcc-13 is configured `--enable-default-pie`), and for a compile at the
 * default the object's `.gnu.lto_.opts` section lists `-fPIC`; lto-wrapper
 * passes it to both lto1 runs (their saved argument files carry it, the
 * whole-program one with `-flinker-output=dyn`). All measured; every link of a
 * corpus unit in the runs LTO.md reports exited 0. So the compile stays the
 * find step's, bar the two changes that make it an LTO compile.
 */
export function gccCompileFlags(flags) {
  return ltoCompileFlags(flags, 'full');
}

/**
 * The link line, before `-o <out> <obj>`: one object, `-shared`, and
 * `-save-temps`, which keeps what lto1 wrote -- among it the assembly of the one
 * partition, the post-LTO code this probe reads. The link runs to the end (the
 * shared object is written and compared too). `linkPlugin` puts WipePinGcc on
 * the link line (configuration ii).
 */
export function gccLinkArgs({ opt, linkPlugin = null }) {
  if (typeof opt !== 'string' || !/^-O[0-3s]$/.test(opt)) throw new Error(`bad opt ${JSON.stringify(opt)}`);
  const a = [opt, '-flto', '-shared', '-save-temps'];
  if (linkPlugin) a.push(`-fplugin=${linkPlugin}`);
  return a;
}

/**
 * The section table of an ELF64 little-endian file, read from its bytes: every
 * section's name, type, file offset and size. Extended numbering (e_shnum 0,
 * e_shstrndx SHN_XINDEX) is followed. Anything else -- not ELF, ELF32, big
 * endian, a table or a name that runs past the end -- is `ok: false` with the
 * reason, and the caller fails closed on it.
 *
 * @param {Buffer|null} buf
 * @returns {{ok: boolean, sections: {name: string, type: number, offset: number, size: number}[], problem: string|null}}
 */
export function elfSections(buf) {
  const no = (problem) => ({ ok: false, sections: [], problem });
  if (!buf || buf.length < 64) return no('too short for an ELF64 header');
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return no('not ELF');
  if (buf[4] !== 2) return no('not ELF64');
  if (buf[5] !== 1) return no('not little-endian');
  const shoff = Number(buf.readBigUInt64LE(0x28));
  const shentsize = buf.readUInt16LE(0x3a);
  let shnum = buf.readUInt16LE(0x3c);
  let shstrndx = buf.readUInt16LE(0x3e);
  if (shoff === 0) return { ok: true, sections: [], problem: null };
  if (shentsize < 64) return no(`section header entries of ${shentsize} bytes`);
  const header = (i) => {
    const o = shoff + i * shentsize;
    return {
      name: buf.readUInt32LE(o), type: buf.readUInt32LE(o + 4),
      offset: Number(buf.readBigUInt64LE(o + 24)), size: Number(buf.readBigUInt64LE(o + 32)), link: buf.readUInt32LE(o + 40),
    };
  };
  if (shoff + shentsize > buf.length) return no('the section header table starts past the end');
  const first = header(0);
  if (shnum === 0) shnum = first.size;
  if (shstrndx === 0xffff) shstrndx = first.link;
  if (shoff + shnum * shentsize > buf.length) return no('the section header table runs past the end');
  if (shstrndx >= shnum) return no('the section-name table index is out of range');
  const strtab = header(shstrndx);
  if (strtab.offset + strtab.size > buf.length) return no('the section-name table runs past the end');
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const h = header(i);
    const start = strtab.offset + h.name;
    const end = buf.indexOf(0, start);
    if (h.name >= strtab.size || end === -1 || end > strtab.offset + strtab.size) return no(`section ${i}: its name runs past the section-name table`);
    sections.push({ name: buf.toString('latin1', start, end), type: h.type, offset: h.offset, size: h.size });
  }
  return { ok: true, sections, problem: null };
}

/**
 * What an object is, for this probe. ./lto.mjs's objectKind first (missing,
 * empty, LLVM bitcode, ELF, other); an ELF file is then 'gcc-lto' when at least
 * one of its sections is named `.gnu.lto_...`, 'elf' when none is (a plain
 * object: what a compile without `-flto` writes), and 'elf-unreadable' when its
 * section table cannot be read. Anything but 'gcc-lto' means the compile did not
 * produce what gcc's LTO link consumes, and the cell must not be scored as LTO.
 */
export function gccObjectKind(buf) {
  const k = objectKind(buf);
  if (k !== 'elf') return k;
  const s = elfSections(buf);
  if (!s.ok) return 'elf-unreadable';
  return s.sections.some((x) => x.name.startsWith('.gnu.lto_')) ? 'gcc-lto' : 'elf';
}

/** The bytes of the named section as latin1 text, or null when there is no such section (or no readable table). */
export function sectionText(buf, name) {
  const s = elfSections(buf);
  if (!s.ok) return null;
  const x = s.sections.find((y) => y.name === name);
  if (!x || x.offset + x.size > buf.length) return null;
  return buf.toString('latin1', x.offset, x.offset + x.size);
}

/**
 * Whether the object's `.gnu.lto_.opts` section -- the compile's options, as
 * lto-wrapper reads them at link time -- names a `-fplugin=`. A plugin-on
 * compile's does (measured); whether lto1 then loads that plugin is what the
 * preflight measures, and it does not. null when the section is missing.
 */
export function optsNamePlugin(buf) {
  const t = sectionText(buf, '.gnu.lto_.opts');
  return t === null ? null : t.includes('-fplugin=');
}

/**
 * The files gcc-13 13.3.0 writes for a one-object `-flto -shared -save-temps`
 * link, as suffixes of the basename of -o. Measured; none of it is documented
 * anywhere the probe could cite:
 *
 *   WPA_ONE_LTRANS  lto1 run twice -- whole-program analysis (`-fwpa`), then one
 *                   partition (`-fltrans`) -- the shape every link of a corpus
 *                   unit has: the shared object itself, `.lto_wrapper_args`,
 *                   `.ltrans.out`, `.ltrans0.ltrans.args.0`, `.ltrans0.ltrans.o`,
 *                   `.ltrans0.ltrans.s` (the assembly read), `.ltrans0.ltrans_args`,
 *                   `.ltrans0.o`, `.ltrans_args`, `.res`, `.wpa.args.0`
 *   PARTITION_NONE  `-flto-partition=none`: lto1 run once, no partition files;
 *                   the assembly is `.lto.o.s`
 *
 * All of them land next to -o, whatever the working directory (plain
 * -save-temps; `-save-temps=obj` from another directory kept only nine of the
 * eleven). The probe runs each link in the object's own directory with -o
 * beside the object, so "the names that appeared" is the complete list.
 */
const WPA_ONE_LTRANS = Object.freeze(['', '.lto_wrapper_args', '.ltrans.out', '.ltrans0.ltrans.args.0', '.ltrans0.ltrans.o',
  '.ltrans0.ltrans.s', '.ltrans0.ltrans_args', '.ltrans0.o', '.ltrans_args', '.res', '.wpa.args.0']);
const PARTITION_NONE = Object.freeze(['', '.lto.o', '.lto.o.args.0', '.lto.o.s', '.lto_wrapper_args', '.ltrans_args', '.res']);
export const LAYOUTS = Object.freeze({ 'wpa+1-ltrans': WPA_ONE_LTRANS, 'partition-none': PARTITION_NONE });
export const EXPECTED_LAYOUT = 'wpa+1-ltrans';

function checkBase(outBase) {
  if (typeof outBase !== 'string' || !outBase || /[\\/]/.test(outBase)) throw new Error(`bad output basename ${JSON.stringify(outBase)}`);
}

/**
 * @returns {{expected: string[], read: string, so: string}} every name the link
 *   must write (sorted), the assembly the probe reads, and the shared object.
 */
export function gccExpectedOutputs({ outBase }) {
  checkBase(outBase);
  return { expected: WPA_ONE_LTRANS.map((s) => outBase + s).sort(), read: `${outBase}.ltrans0.ltrans.s`, so: outBase };
}

/**
 * Which layout a link wrote, from the names that appeared: one of LAYOUTS,
 * 'no-lto' (the shared object alone: lto1 never ran, as for an object without
 * `.gnu.lto_` sections), 'wpa+<n>-ltrans' for more than one partition,
 * 'nothing-written', or 'other'. A word for the problem text; the check itself
 * is pickOutput's exact comparison.
 */
export function gccLayoutOf(names, outBase) {
  checkBase(outBase);
  const set = new Set(names || []);
  if (!set.size) return 'nothing-written';
  for (const [word, suffixes] of Object.entries(LAYOUTS)) {
    if (suffixes.length === set.size && suffixes.every((s) => set.has(outBase + s))) return word;
  }
  if (set.size === 1 && set.has(outBase)) return 'no-lto';
  const parts = new Set();
  for (const n of set) {
    const m = /\.ltrans(\d+)\.ltrans\.s$/.exec(n);
    if (m) parts.add(m[1]);
  }
  if (parts.size > 1) return `wpa+${parts.size}-ltrans`;
  return 'other';
}

/**
 * The line WipePinGcc prints when lto1 loads it (compiler/gcc-repair/src/
 * WipePinGcc.cpp, plugin_init; the fixture loop's checker holds the same text
 * as LTO_REFUSAL). It is printed after the stale-record rule has removed
 * whatever was at WPIN_OUT, so a refused load still clears that file.
 */
export const GCC_LTO_REFUSAL = 'WipePinGcc: refusing to install: loaded into the LTO back end, where this pass does '
  + 'not run; load it into the compile step instead';

/**
 * How many times one link prints it: once per lto1 process that loads the
 * plugin. For a one-object `-shared` link, measured, lto1 runs twice -- the
 * whole-program analysis and the one partition -- so twice. `-flto-partition=none`
 * runs lto1 once (measured: once), and is graded FAILED like any other count.
 */
export const EXPECTED_REFUSALS = 2;

/** The non-empty lines of a stderr text, carriage returns dropped. [] for null. */
export function stderrLines(text) {
  if (typeof text !== 'string') return [];
  return text.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l !== '');
}

/** The number of lines WipePinGcc printed ("WipePinGcc: ..."). On a stock link it must be 0. */
export function wipePinGccLines(stderr) {
  return stderrLines(stderr).filter((l) => l.startsWith('WipePinGcc:')).length;
}

/**
 * A configuration (ii) link's stderr, read against GCC_LTO_REFUSAL and against
 * the stock link of the same object. The stock link's stderr is not always
 * empty -- lto1 runs its warnings at link time, without the compile's `-w` --
 * so "nothing else" means: once the refusal lines are taken out, what is left is
 * the stock link's stderr, line for line.
 *
 * @returns {{count: number, restIsStock: boolean, exact: boolean}}
 */
export function refusalReading(stderr, stockStderr) {
  if (typeof stderr !== 'string') return { count: 0, restIsStock: false, exact: false };
  const lines = stderrLines(stderr);
  const stock = stderrLines(stockStderr);
  const count = lines.filter((l) => l === GCC_LTO_REFUSAL).length;
  const rest = lines.filter((l) => l !== GCC_LTO_REFUSAL);
  const restIsStock = rest.length === stock.length && rest.every((l, i) => l === stock[i]);
  return { count, restIsStock, exact: count === EXPECTED_REFUSALS && restIsStock };
}

/**
 * Configuration (ii), graded. For every link with WipePinGcc on the link line
 * only (both units of every cell that is not NOT_LTO): exit 0; the sentinel at
 * WPIN_OUT removed and no record written (`state` 'removed', from ./lto.mjs's
 * linkPluginState); the refusal exactly EXPECTED_REFUSALS times and otherwise
 * the stock link's stderr; the expected file layout; and the post-LTO assembly
 * and the shared object byte-identical to the stock link of the same object.
 * FAILED as vacuous when no such link exists.
 *
 * rows: [{id, opt, outcome, linkPlugin: {w, wo}}], each side {rc, state,
 * refusals, restIsStock, layout, asmEqualsStock, soEqualsStock}.
 */
export function gradeLinkPluginGcc(rows) {
  const considered = rows.filter((r) => r.outcome !== 'NOT_LTO' && r.linkPlugin);
  const violations = [];
  for (const r of considered) {
    for (const side of ['w', 'wo']) {
      const x = r.linkPlugin[side];
      const at = `${r.id} ${r.opt} ${side}`;
      if (!x) { violations.push(`${at}: no link with the plugin on the link line`); continue; }
      if (x.rc !== 0) violations.push(`${at}: the link exited ${x.rc}`);
      if (x.state !== 'removed') violations.push(`${at}: WPIN_OUT after the link is ${x.state}, expected removed`);
      if (x.refusals !== EXPECTED_REFUSALS) {
        violations.push(`${at}: the LTO refusal printed ${x.refusals ?? 0} time(s), expected ${EXPECTED_REFUSALS} `
          + '(the whole-program analysis and one partition)');
      }
      if (x.restIsStock !== true) violations.push(`${at}: the linker's stderr, less the refusal lines, is not the stock link's`);
      if (x.layout !== EXPECTED_LAYOUT) violations.push(`${at}: the link wrote the ${x.layout} layout, expected ${EXPECTED_LAYOUT}`);
      // false: both were read and differ; null: one of them was not read (a
      // failed link, or a layout whose assembly this probe does not read).
      const same = (b) => (b === false ? 'is not byte-identical to' : 'could not be compared with');
      if (x.asmEqualsStock !== true) violations.push(`${at}: the post-LTO assembly ${same(x.asmEqualsStock)} the stock link's`);
      if (x.soEqualsStock !== true) violations.push(`${at}: the shared object ${same(x.soEqualsStock)} the stock link's`);
    }
  }
  if (!considered.length) return { held: false, links: 0, violations: ['vacuous: no link with the plugin on the link line'] };
  return { held: violations.length === 0, links: considered.length * 2, violations };
}

/**
 * Where the loss happens. The clang probe reads the compile-stage bitcode with
 * llvm-dis-18; gcc's reader is lto-dump-13, which reads the GIMPLE cc1 streamed
 * into an object's `.gnu.lto_` sections -- the code lto1 starts from -- and
 * prints one function with `-dump-body=<fn>`. Measured on gcc-13 13.3.0: the
 * body goes to stderr and `GIMPLE body of function: <fn>` to stdout; a name the
 * object does not define (a declaration, a static function inlined away, and
 * any name at all in an object without `.gnu.lto_` sections) prints
 * `<tool>: error: Function not found.` on stderr and exits 0; a file it cannot
 * open exits 1. So the exit code does not say that a body was printed, and the
 * stdout line does. (Without `-o`, lto-dump-13 also writes an empty
 * `<object stem>.s` beside the object; the probe passes `-o /dev/null`.)
 *
 * @param {{rc: number, stdout: string, stderr: string}} r  one `-dump-body=<fn>` run
 * @returns {{state: 'body'|'not-defined'|'unreadable', body: string|null}}
 */
export function gimpleBodyOf(r, fn) {
  const out = r && typeof r.stdout === 'string' ? stderrLines(r.stdout) : null;
  const err = r && typeof r.stderr === 'string' ? r.stderr : null;
  if (!r || r.rc !== 0 || out === null || err === null) return { state: 'unreadable', body: null };
  if (out.length === 1 && out[0] === `GIMPLE body of function: ${fn}` && err.trim() !== '') return { state: 'body', body: err };
  const e = stderrLines(err);
  if (out.length === 0 && e.length === 1 && /: error: Function not found\.$/.test(e[0])) return { state: 'not-defined', body: null };
  return { state: 'unreadable', body: null };
}

const MEMSET_NAMES = new Set(['memset', '__builtin_memset', '__builtin___memset_chk', '__memset_chk']);
const GIMPLE_CALL = /^\s*(?:[^=]*[^=\s] = )?([A-Za-z_][\w.]*) \((.*)\);(?: \[[^\]]*\])*$/;
const PIN_BARRIER = /^\s*__asm__ __volatile__\(""\s*:\s*:\s*"g" (.+) : "memory"\);$/;

/** The top-level, comma-separated arguments of a GIMPLE call, e.g. `&key, 0, 32`. */
function gimpleArgs(text) {
  const args = [];
  let depth = 0;
  let cur = '';
  for (const ch of text) {
    if ('([<{'.includes(ch)) depth++;
    else if (')]>}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { args.push(cur.trim()); cur = ''; } else cur += ch;
  }
  args.push(cur.trim());
  return args;
}

/**
 * Zero-fill memset calls in GIMPLE bodies (gimpleBodyOf's), split as the clang
 * probe splits llvm.memset by its volatile operand. A call to `memset`,
 * `__builtin_memset` or a checking form whose fill is the literal 0 is `pinned`
 * when the next statement is the barrier WipePinGcc puts there (buildPin in
 * compiler/gcc-repair/src/WipePinGcc.cpp) -- `__asm__ __volatile__("" : : "g"
 * <dest> : "memory")` naming the memset's own destination -- and `plain`
 * otherwise. `helperCalls` counts calls, in any of the bodies, to another of the
 * named functions: a wipe still behind a helper call reaches the link as a call,
 * not as a memset. `bodies` maps each name to its body, or to null when the
 * object does not define it; `defined` lists the names that had a body.
 *
 * @param {Record<string, string|null>} bodies
 * @returns {{defined: string[], plain: number, pinned: number, helperCalls: number}}
 */
export function zeroMemsetsInGimple(bodies) {
  const names = Object.keys(bodies || {});
  const out = { defined: [], plain: 0, pinned: 0, helperCalls: 0 };
  for (const name of names) {
    const body = bodies[name];
    if (typeof body !== 'string') continue;
    out.defined.push(name);
    const lines = body.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.trim() !== '' && !/^\s*# DEBUG\b/.test(l));
    lines.forEach((line, i) => {
      const c = GIMPLE_CALL.exec(line);
      if (!c) return;
      if (names.includes(c[1]) && c[1] !== name) { out.helperCalls++; return; }
      if (!MEMSET_NAMES.has(c[1])) return;
      const a = gimpleArgs(c[2]);
      if (a.length < 3 || a[1] !== '0') return;
      const b = i + 1 < lines.length ? PIN_BARRIER.exec(lines[i + 1]) : null;
      if (b && b[1].trim() === a[0]) out.pinned++; else out.plain++;
    });
  }
  return out;
}

/**
 * The reader's positive control, per object: the find step's CONTROL function
 * (vgctl_control) wipes its buffer with one `__builtin_memset` that a later
 * use keeps alive, and no configuration here names it for pinning, so a reader
 * that works reads exactly one plain zero-fill memset in it. A reading of an
 * object whose control does not read that way is not used: "holds no memset"
 * from a reader that cannot see the control's memset would be vacuous.
 */
export function gimpleControlOk(controlBody) {
  if (typeof controlBody !== 'string') return false;
  const m = zeroMemsetsInGimple({ vgctl_control: controlBody });
  return m.plain === 1 && m.pinned === 0;
}

/** Zero-fill memsets plus named-helper calls: what can carry a wipe to the link. */
const carriers = (g) => g.plain + g.pinned + g.helperCalls;

/**
 * Whether the compile-stage GIMPLE of the wipe-kept unit still carries the wipe
 * to the link: more zero-fill memsets or named-helper calls in the requested
 * functions than the ablated unit's. null when either was not read.
 */
export function carriesWipe(wOff, woOff) {
  if (!wOff || !woOff) return null;
  return carriers(wOff) > carriers(woOff);
}

/**
 * The outcome of one cell (configuration i: plugin at compile time, stock
 * link): NOT_LTO in front, then the repair loop's own outcomeOf
 * (../../lib/outcome.mjs), unchanged, over the two records as
 * ../../lib/pin-record.mjs read them.
 *
 *   NOT_LTO  an object that exists is not a gcc LTO object, or a stock link
 *            wrote anything but the expected layout. Ahead of everything: such a
 *            cell measured something other than gcc's LTO, and its verdicts must
 *            not be counted as LTO's.
 *
 * Everything after it is outcomeOf's precedence, so a refused record, a
 * requested name that did not resolve (bar its one tolerated shape), or a
 * positive control missing from a plugin-on link is BROKEN_REPAIR here as it is
 * in the repair loop, and PIN_INEFFECTIVE is the word that would say the LTO
 * link undid the pin.
 *
 * @param {{notLto?: string[], baseline: object, repaired: object, recordW: object, recordWo: object, controlOnOk: boolean}} a
 */
export function gccLtoOutcome({ notLto = [], baseline, repaired, recordW, recordWo, controlOnOk }) {
  if (notLto.length) return { outcome: 'NOT_LTO', reason: notLto.join('; ') };
  const o = outcomeOf(baseline, repaired, recordW, recordWo, controlOnOk);
  return { outcome: o.outcome, reason: o.reason };
}

/**
 * The selection at one level, from the tracked repair rows of one compiler:
 * ./lto.mjs's selectErasureIds over the rows' `baseline` -- the erasure files
 * whose baseline is WIPE_ELIMINATED, or with `allRemovable` every file of the
 * `removable` idiom. Sorted, each id once.
 */
export function selectIds(rows, { cc, opt, allRemovable = false }) {
  return selectErasureIds(rows, { cc, opt, allRemovable, verdictField: 'baseline' });
}

/**
 * Counts for one level's rows. Pure; the probe prints it.
 *
 * `trackedDiff` lists the cells whose LTO baseline differs from the tracked,
 * non-LTO gcc-13 baseline for the same (id, level); `addedEliminations` the
 * ones among them that survived without LTO and are eliminated with it -- an
 * elimination the LTO build adds, in the compile or in the link (`stage` says
 * which: whether w/off still carries the wipe into the link) -- with their
 * outcome.
 */
export function summarizeGccGroup(rows) {
  const n = (f) => rows.filter(f).length;
  const lto = rows.filter((r) => r.outcome !== 'NOT_LTO');
  const outcomes = Object.fromEntries(LTO_OUTCOMES.map((o) => [o, n((r) => r.outcome === o)]));
  const lpLinks = lto.flatMap((r) => (r.linkPlugin ? [r.linkPlugin.w, r.linkPlugin.wo] : [])).filter(Boolean);
  const det = rows.flatMap((r) => (r.deterministic ? Object.values(r.deterministic).flatMap((d) => [d.asm, d.so]) : []));
  const dryAsm = rows.flatMap((r) => (r.dryAsmEqualsOff ? Object.values(r.dryAsmEqualsOff) : []));
  const drySo = rows.flatMap((r) => (r.drySoEqualsOff ? Object.values(r.drySoEqualsOff) : []));
  const stock = rows.map((r) => r.stockStderr).filter(Boolean);
  const diff = lto.filter((r) => r.tracked !== r.baseline);
  const refusalHistogram = {};
  for (const x of lpLinks) refusalHistogram[x.refusals] = (refusalHistogram[x.refusals] || 0) + 1;
  const elim = lto.filter((r) => r.baseline === ELIMINATED);
  const surv = lto.filter((r) => r.baseline === SURVIVED);
  const read = (r) => !!(r.gimple && r.gimple.wOff && r.gimple.woOff && r.gimple.wOn);
  return {
    cells: rows.length,
    baselineEliminated: n((r) => r.outcome !== 'NOT_LTO' && r.baseline === ELIMINATED),
    baselineSurvived: n((r) => r.outcome !== 'NOT_LTO' && r.baseline === SURVIVED),
    baselineOther: n((r) => r.outcome !== 'NOT_LTO' && r.baseline !== ELIMINATED && r.baseline !== SURVIVED),
    trackedDiff: diff.map((r) => ({ id: r.id, tracked: r.tracked, lto: r.baseline, outcome: r.outcome })),
    addedEliminations: diff.filter((r) => r.tracked === SURVIVED && r.baseline === ELIMINATED)
      .map((r) => ({ id: r.id, outcome: r.outcome })),
    outcomes,
    dry: gradeDryRun(rows),
    linkPlugin: {
      links: lpLinks.length,
      removed: lpLinks.filter((x) => x.state === 'removed').length,
      recordWritten: lpLinks.filter((x) => x.state === 'record-written').length,
      sentinelKept: lpLinks.filter((x) => x.state === 'sentinel-kept').length,
      refusalHistogram,
      restIsStock: lpLinks.filter((x) => x.restIsStock === true).length,
      layoutExpected: lpLinks.filter((x) => x.layout === EXPECTED_LAYOUT).length,
      asmEqualsStock: lpLinks.filter((x) => x.asmEqualsStock === true).length,
      soEqualsStock: lpLinks.filter((x) => x.soEqualsStock === true).length,
      cells: lto.filter((r) => !!r.linkPlugin).length,
      verdictEqualsBaseline: lto.filter((r) => r.linkPlugin && r.linkPlugin.verdict === r.baseline).length,
      grade: gradeLinkPluginGcc(rows),
    },
    determinism: { pairs: det.length, identical: det.filter((x) => x === true).length },
    dryAsmEqualsOff: { of: dryAsm.length, equal: dryAsm.filter((x) => x === true).length },
    drySoEqualsOff: { of: drySo.length, equal: drySo.filter((x) => x === true).length },
    stockLinks: {
      links: stock.reduce((k, s) => k + s.links, 0),
      withWipePinGccLine: stock.reduce((k, s) => k + s.withWipePinGccLine, 0),
      nonEmpty: stock.reduce((k, s) => k + s.nonEmpty, 0),
    },
    labelsOnly: {
      baseline: n((r) => r.labelsOnly && r.labelsOnly.baseline === true),
      repaired: n((r) => r.labelsOnly && r.labelsOnly.repaired === true),
    },
    // Where the loss happens, from the compile-stage GIMPLE (lto-dump on the
    // objects): does w/off still carry the wipe to the link, and does w/on hold
    // a pinned memset? Eliminated cells, and survived ones (with --all-removable).
    stage: {
      eliminated: elim.length,
      wOffCarries: elim.filter((r) => read(r) && carriesWipe(r.gimple.wOff, r.gimple.woOff)).length,
      wOffHoldsNone: elim.filter((r) => read(r) && r.gimple.wOff.plain + r.gimple.wOff.pinned === 0).length,
      wOnPinned: elim.filter((r) => read(r) && r.gimple.wOn.pinned > 0).length,
      unread: elim.filter((r) => !read(r)).length,
      survived: surv.length,
      survivedWOffCarries: surv.filter((r) => read(r) && carriesWipe(r.gimple.wOff, r.gimple.woOff)).length,
      survivedUnread: surv.filter((r) => !read(r)).length,
    },
  };
}

/**
 * The run is broken (exit 2) when any level has a NOT_LTO cell, a relink that
 * was not byte-identical, a dry-run control that did not hold where there was
 * something to control, a configuration (ii) that was not HELD, or a stock
 * link on which WipePinGcc printed anything (the plugin reached lto1 without
 * being on the link line). Returns the reasons, empty when none.
 */
export function brokenReasons(groups) {
  const why = [];
  for (const { opt, s } of groups) {
    if (s.outcomes.NOT_LTO > 0) why.push(`${opt}: ${s.outcomes.NOT_LTO} NOT_LTO cell(s)`);
    if (s.determinism.identical !== s.determinism.pairs) why.push(`${opt}: ${s.determinism.pairs - s.determinism.identical} relink(s) not byte-identical`);
    if (s.baselineEliminated > 0 && !s.dry.held) why.push(`${opt}: the dry-run red control did not hold`);
    if (!s.linkPlugin.grade.held) why.push(`${opt}: configuration (ii) FAILED`);
    if (s.stockLinks.withWipePinGccLine > 0) why.push(`${opt}: WipePinGcc printed on ${s.stockLinks.withWipePinGccLine} stock link(s)`);
  }
  return why;
}

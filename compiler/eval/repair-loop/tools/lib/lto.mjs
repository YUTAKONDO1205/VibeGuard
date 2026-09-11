/**
 * The LTO probe's pure parts. Nothing here compiles, links, reads a file or
 * looks at a directory: ../lto-probe.mjs runs the tools and hands in what it
 * saw, and every decision about what that means is made here, where the tests
 * (../../test/lto-probe.test.mjs) can reach it without a compiler.
 *
 * The question is the one compiler/llvm-repair/README.md leaves open under
 * "Other forms": a `-flto` / `-flto=thin` compile with WipePin loaded writes a
 * record and its bitcode carries the volatile memset, but what the LTO backend
 * then does with it was not measured. The probe answers it with the find
 * step's own verdict (`verdictOf` from ../../../ai-generated/lib/ablation-cell.mjs,
 * imported by the probe, never copied), applied to the assembly the LTO
 * backend writes.
 *
 * Plugin records are read here with JSON.parse and three fields only --
 * `dryRun`, `pinnedCount`, `module` -- on purpose, not through
 * ../../lib/pin-record.mjs: the probe must keep working while the record's
 * schema moves, and those three are what it needs to say that the repair ran on
 * the unit it was meant for and whether it changed anything. The price is
 * stated in LTO.md: a requested name that did not resolve is not seen here.
 */

export const ELIMINATED = 'WIPE_ELIMINATED';
export const SURVIVED = 'WIPE_SURVIVED';

/**
 * The two LTO forms. `compile` replaces the find step's `-S`; `link` goes on the
 * link line so that clang's driver hands lld the matching `-plugin-opt=`s
 * (measured with `-###` on clang 18.1.3: `-plugin-opt=O<n>` from the -O flag,
 * `-plugin-opt=thinlto` for thin). ThinLTO is pinned to one backend job, as
 * ../../../../llvm-pass/scripts/observe-config.sh pins it for its link-stage
 * cells.
 */
export const MODES = Object.freeze({
  full: Object.freeze({ compile: '-flto', link: Object.freeze(['-flto']) }),
  thin: Object.freeze({ compile: '-flto=thin', link: Object.freeze(['-flto=thin', '-Wl,--thinlto-jobs=1']) }),
});

/** The two ways to get post-LTO assembly. `asm` is the measurement; `llvm+llc` the fallback. */
export const EMITS = Object.freeze(['asm', 'llvm+llc']);

/**
 * The find step's FLAGS with `-S` turned into `-c` and the LTO flag added.
 *
 * Refuses rather than guesses: FLAGS must carry `-S` exactly once and nothing
 * that already decides the output form. If the find step's flags ever change
 * shape, the probe stops instead of quietly compiling something else.
 */
export function ltoCompileFlags(flags, mode) {
  if (!MODES[mode]) throw new Error(`unknown LTO mode ${JSON.stringify(mode)}`);
  if (!Array.isArray(flags)) throw new Error('FLAGS is not an array');
  const nS = flags.filter((f) => f === '-S').length;
  if (nS !== 1) throw new Error(`the find step's FLAGS carry -S ${nS} time(s); the probe replaces exactly one`);
  const clash = flags.filter((f) => f === '-c' || f === '-E' || f === '-emit-llvm' || /^-f(no-)?lto\b/.test(f));
  if (clash.length) throw new Error(`the find step's FLAGS already decide the output form (${clash.join(' ')})`);
  return [...flags.map((f) => (f === '-S' ? '-c' : f)), MODES[mode].compile];
}

/**
 * The link line, before `-o <out> <obj>`: one object, `-shared`, lld, and the
 * switch that makes lld stop after the LTO backend and write its output.
 * `linkPlugin` puts a pass plugin on the link line (configuration ii).
 *
 * The fallback (`llvm+llc`) keeps `--lto-emit-asm`, so that nothing is ever
 * assembled or linked, and adds `--save-temps`, whose `precodegen.bc` is the
 * module after the LTO optimisation pipeline and before code generation; llc
 * turns that into assembly. Two spellings that look like it are not it, both
 * measured on lld 18.1.3: `--lto-emit-llvm` does not exist ("unknown
 * argument"), and `--plugin-opt=emit-llvm` writes the module BEFORE the LTO
 * optimisation pipeline -- `--lto-debug-pass-manager` prints no pass at all
 * for it, a plugin on its link line is never even asked to register, and at
 * -O1 its output still holds the memset the LTO link removes. A fallback built
 * on it would have judged pre-optimisation code as post-LTO code.
 */
export function ltoLinkArgs({ opt, mode, emit = 'asm', linkPlugin = null }) {
  if (!MODES[mode]) throw new Error(`unknown LTO mode ${JSON.stringify(mode)}`);
  if (!EMITS.includes(emit)) throw new Error(`unknown emit ${JSON.stringify(emit)}`);
  if (typeof opt !== 'string' || !/^-O[0-3s]$/.test(opt)) throw new Error(`bad opt ${JSON.stringify(opt)}`);
  const a = [opt, ...MODES[mode].link, '-fuse-ld=lld', '-shared', '-Wl,--lto-emit-asm'];
  if (emit === 'llvm+llc') a.push('-Wl,--save-temps');
  if (linkPlugin) a.push(`-Wl,--load-pass-plugin=${linkPlugin}`);
  return a;
}

/**
 * The llc level for the fallback, matching what the driver asks of lld:
 * `-Os` becomes LTO level 2 (measured with `-###`: `-plugin-opt=O2`), and the
 * size preference travels as function attributes in the bitcode.
 */
export function llcOptFor(opt) {
  const m = { '-O0': '-O0', '-O1': '-O1', '-O2': '-O2', '-O3': '-O3', '-Os': '-O2' };
  if (!(opt in m)) throw new Error(`bad opt ${JSON.stringify(opt)}`);
  return m[opt];
}

/**
 * What an object's first bytes say it is. LLVM bitcode starts `BC` 0xC0DE; an
 * ELF object 0x7F `ELF`. Anything but 'bitcode' means the compile did not
 * produce what an LTO link consumes, and the cell must not be scored as LTO.
 */
export function objectKind(buf) {
  if (buf === null || buf === undefined) return 'missing';
  if (buf.length === 0) return 'empty';
  if (buf.length >= 4 && buf[0] === 0x42 && buf[1] === 0x43 && buf[2] === 0xc0 && buf[3] === 0xde) return 'bitcode';
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'elf';
  return 'other';
}

/**
 * The files lld 18.1.3 writes for a single-object link, by form, and the one the
 * probe reads. Measured, not documented anywhere the probe could cite:
 *
 *   --lto-emit-asm, full LTO   <-o>.lto.s                     next to -o
 *   --lto-emit-asm, ThinLTO    <basename of -o>.lto.<stem>.s  next to the OBJECT
 *
 * and with --save-temps added (the fallback), besides the assembly:
 *
 *   full LTO   <-o>.0.0.preopt.bc .0.2.internalize.bc .0.4.opt.bc .0.5.precodegen.bc
 *              .resolution.txt
 *   ThinLTO    <-o>.0.0.preopt.bc .0.2.internalize.bc .index.bc .index.dot .resolution.txt,
 *              and, named after the OBJECT: <obj>.0.preopt.bc .1.promote.bc
 *              .2.internalize.bc .3.import.bc .4.opt.bc .5.precodegen.bc
 *
 * Nothing is written at -o itself. The probe puts -o next to the object, so all
 * of them land in the object's directory. The names also say which backend
 * ran: a thin object that lld linked as full LTO (or the reverse) writes the
 * other form's names, and is refused.
 *
 * @returns {{expected: string[], read: string}} every name the link must write
 *   (sorted), and the one the probe reads: the assembly, or in the fallback the
 *   pre-codegen bitcode.
 */
export function expectedOutputs({ mode, emit, outBase, objStem }) {
  if (!MODES[mode]) throw new Error(`unknown LTO mode ${JSON.stringify(mode)}`);
  if (!EMITS.includes(emit)) throw new Error(`unknown emit ${JSON.stringify(emit)}`);
  const asm = mode === 'full' ? `${outBase}.lto.s` : `${outBase}.lto.${objStem}.s`;
  if (emit === 'asm') return { expected: [asm], read: asm };
  const obj = `${objStem}.o`;
  const temps = mode === 'full'
    ? ['.0.0.preopt.bc', '.0.2.internalize.bc', '.0.4.opt.bc', '.0.5.precodegen.bc', '.resolution.txt'].map((s) => outBase + s)
    : [...['.0.0.preopt.bc', '.0.2.internalize.bc', '.index.bc', '.index.dot', '.resolution.txt'].map((s) => outBase + s),
      ...['.0.preopt.bc', '.1.promote.bc', '.2.internalize.bc', '.3.import.bc', '.4.opt.bc', '.5.precodegen.bc'].map((s) => obj + s)];
  const read = mode === 'full' ? `${outBase}.0.5.precodegen.bc` : `${obj}.5.precodegen.bc`;
  return { expected: [asm, ...temps].sort(), read };
}

/**
 * The link's output, from the names that appeared in the directory: exactly the
 * expected set, or a problem that names what differs (basenames only).
 */
export function pickOutput(newNames, { expected, read }) {
  const names = [...(newNames || [])].sort();
  const want = [...expected].sort();
  if (names.length === want.length && names.every((n, i) => n === want[i])) return { ok: true, name: read, problem: null };
  if (!names.length) return { ok: false, name: null, problem: 'no output written' };
  const extra = names.filter((n) => !want.includes(n));
  const missing = want.filter((n) => !names.includes(n));
  return { ok: false, name: null, problem: `unexpected output(s)${extra.length ? ` ${extra.join(',')}` : ''}`
    + `${missing.length ? `; missing ${missing.join(',')}` : ''} (expected ${want.join(',')})` };
}

/**
 * A plugin record, read with JSON.parse and three fields only. `text` is the
 * file's content or null when there was no file. `expect` is what the compile
 * that should have written it asked for: `{dryRun, module}`.
 *
 * Refused (ok: false, with named problems): no file, not a JSON object, a field
 * of the wrong type, a `module` that is a path, a record from another unit, a
 * record whose dry-run flag is not the one requested, a dry run that pinned.
 */
export function readRecordFields(text, expect = {}) {
  if (typeof text !== 'string') return { ok: false, problems: ['record-missing'] };
  let r;
  try { r = JSON.parse(text); } catch { return { ok: false, problems: ['not-json'] }; }
  if (!r || typeof r !== 'object' || Array.isArray(r)) return { ok: false, problems: ['not-an-object'] };
  const problems = [];
  if (typeof r.dryRun !== 'boolean') problems.push('dryRun-not-boolean');
  if (!Number.isInteger(r.pinnedCount) || r.pinnedCount < 0) problems.push('pinnedCount-not-a-count');
  if (typeof r.module !== 'string' || r.module === '' || /[\\/]/.test(r.module)) problems.push('module-not-a-basename');
  if (!problems.length) {
    if (typeof expect.dryRun === 'boolean' && r.dryRun !== expect.dryRun) problems.push(`dryRun-${r.dryRun}-expected-${expect.dryRun}`);
    if (typeof expect.module === 'string' && r.module !== expect.module) problems.push('module-mismatch');
    if (r.dryRun === true && r.pinnedCount !== 0) problems.push('dry-run-pinned');
  }
  if (problems.length) return { ok: false, problems };
  return { ok: true, problems: [], dryRun: r.dryRun, pinnedCount: r.pinnedCount, module: r.module };
}

export const LTO_OUTCOMES = Object.freeze(['NOT_LTO', 'NOT_SCORED', 'BROKEN_REPAIR', 'ALREADY_SURVIVED', 'REGRESSED',
  'RETAINED', 'SURVIVED_WITHOUT_PIN', 'PIN_INEFFECTIVE', 'PIN_NOT_APPLIED']);

/**
 * The outcome of one LTO cell (configuration i: plugin at compile time, stock
 * link). The words and their order are the repair loop's (../../lib/outcome.mjs),
 * restated here over the three record fields this probe reads, with one word in
 * front of them:
 *
 *   0. NOT_LTO        an object that exists is not bitcode, or a link wrote
 *                     anything but the one file its form writes. Ahead of
 *                     everything: such a cell measured something other than
 *                     LTO, and its verdicts must not be counted as LTO's.
 *   1. NOT_SCORED     the baseline (w/off, wo/off) is not a WIPE_ verdict.
 *   2. BROKEN_REPAIR  a plugin-on record missing or refused, or the positive
 *                     control not PRESENT in a plugin-on link's assembly.
 *   3. NOT_SCORED     the repaired verdict is not a WIPE_ verdict.
 *   4. the two-by-two table; RETAINED needs the wipe-kept record to have
 *      pinned something, and PIN_INEFFECTIVE (eliminated both ways although
 *      something was pinned) is the word that would say the LTO backend undid
 *      the pin.
 *
 * `notLto` is a list of problems (empty when every object was bitcode and every
 * link wrote what it should).
 */
export function ltoOutcome({ notLto = [], baseline, repaired, recW, recWo, controlOnW, controlOnWo }) {
  if (notLto.length) return { outcome: 'NOT_LTO', reason: notLto.join('; ') };
  const b = baseline ? baseline.verdict : undefined;
  const r = repaired ? repaired.verdict : undefined;
  if (b !== ELIMINATED && b !== SURVIVED) return { outcome: 'NOT_SCORED', reason: `baseline ${b}` };
  const broken = [];
  if (!recW || !recW.ok) broken.push(`w record refused (${recW ? recW.problems.join(',') : 'record-missing'})`);
  if (!recWo || !recWo.ok) broken.push(`wo record refused (${recWo ? recWo.problems.join(',') : 'record-missing'})`);
  if (controlOnW !== true) broken.push('positive control not PRESENT in w/on');
  if (controlOnWo !== true) broken.push('positive control not PRESENT in wo/on');
  if (broken.length) return { outcome: 'BROKEN_REPAIR', reason: broken.join('; ') };
  if (r !== ELIMINATED && r !== SURVIVED) return { outcome: 'NOT_SCORED', reason: `repaired ${r}` };
  const pinned = recW.pinnedCount > 0;
  if (b === SURVIVED) return r === SURVIVED ? { outcome: 'ALREADY_SURVIVED', reason: '' } : { outcome: 'REGRESSED', reason: '' };
  if (r === SURVIVED) {
    return pinned ? { outcome: 'RETAINED', reason: '' }
      : { outcome: 'SURVIVED_WITHOUT_PIN', reason: 'survived with the plugin although the w record pinned nothing' };
  }
  return pinned ? { outcome: 'PIN_INEFFECTIVE', reason: `eliminated after the LTO backend although ${recW.pinnedCount} site(s) were pinned` }
    : { outcome: 'PIN_NOT_APPLIED', reason: 'nothing was pinned' };
}

/**
 * The dry-run red control (configuration iii), graded. Every cell whose LTO
 * baseline is WIPE_ELIMINATED must still read WIPE_ELIMINATED with the plugin
 * loaded at compile time in dry-run mode, and both dry-run records must be
 * valid dry-run records (pinnedCount 0). A control in which no cell had an
 * eliminated baseline is FAILED as vacuous: a control that never ran looks
 * exactly like one that held.
 *
 * rows: [{id, mode, opt, outcome, baseline, dry, recDryW, recDryWo}] with
 * `baseline` and `dry` as verdict words.
 */
export function gradeDryRun(rows) {
  const considered = rows.filter((r) => r.outcome !== 'NOT_LTO' && r.baseline === ELIMINATED);
  const violations = [];
  for (const r of considered) {
    const at = `${r.id} ${r.mode} ${r.opt}`;
    if (r.dry !== ELIMINATED) violations.push(`${at}: the dry run reads ${r.dry}`);
    if (!r.recDryW || !r.recDryW.ok) violations.push(`${at}: w dry-run record refused (${r.recDryW ? r.recDryW.problems.join(',') : 'record-missing'})`);
    if (!r.recDryWo || !r.recDryWo.ok) violations.push(`${at}: wo dry-run record refused (${r.recDryWo ? r.recDryWo.problems.join(',') : 'record-missing'})`);
  }
  const stillEliminated = considered.filter((r) => r.dry === ELIMINATED).length;
  if (!considered.length) return { held: false, considered: 0, stillEliminated: 0, violations: ['vacuous: no cell had an eliminated baseline'] };
  return { held: violations.length === 0, considered: considered.length, stillEliminated, violations };
}

export const SENTINEL = 'lto-probe sentinel: not a WipePin record\n';

/**
 * The line WipePin prints, once per process, when it is loaded into a pipeline
 * built without the pipeline-start extension point -- an LTO link -- and its
 * load-time callback removed a file at WPIN_OUT (compiler/llvm-repair/README.md,
 * "Everything WipePin prints on stderr"). In configuration (ii) the probe
 * always puts SENTINEL at WPIN_OUT first, so this "removed" form is the one
 * expected; the other form ("there was no file at WPIN_OUT ...") would mean the
 * sentinel was not there when the plugin loaded.
 *
 * Before this line existed, (ii) was graded by "the linker's stderr is empty",
 * and an empty stderr is exactly what hid the record the load had just deleted.
 */
export const LINK_LINE_REMOVED = 'WipePin: loaded into a pipeline built without the pipeline-start extension point '
  + '(an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; '
  + 'nothing was pinned in this process, and the file at WPIN_OUT was removed when the plugin loaded';

/**
 * The linker's stderr in configuration (ii), read against LINK_LINE_REMOVED:
 * how many lines are exactly that line, and whether the stderr is that line
 * once and nothing else (no other WipePin line, no linker diagnostic).
 * `stderr` is the text the link printed (null when there was no link).
 */
export function linkLineStderr(stderr) {
  if (typeof stderr !== 'string') return { count: 0, exactlyOnce: false, other: [] };
  const lines = stderr.split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l !== '');
  const count = lines.filter((l) => l === LINK_LINE_REMOVED).length;
  const other = lines.filter((l) => l !== LINK_LINE_REMOVED);
  return { count, exactlyOnce: count === 1 && other.length === 0, other };
}

/**
 * Configuration (ii), graded. For every link with WipePin on the link line only
 * (both units of every cell that is not NOT_LTO): the sentinel at WPIN_OUT was
 * removed and no record written (`state` 'removed'), the linker's stderr is
 * exactly LINK_LINE_REMOVED once, and the assembly is byte-identical to the
 * stock link of the same object. FAILED as vacuous when no such link exists.
 *
 * rows: [{id, mode, opt, outcome, linkPlugin: {w, wo}}], each side
 * {state, asmEqualsStock, stderrLineCount, stderrExactlyLine}.
 */
export function gradeLinkPlugin(rows) {
  const considered = rows.filter((r) => r.outcome !== 'NOT_LTO' && r.linkPlugin);
  const violations = [];
  for (const r of considered) {
    for (const side of ['w', 'wo']) {
      const x = r.linkPlugin[side];
      const at = `${r.id} ${r.mode} ${r.opt} ${side}`;
      if (!x) { violations.push(`${at}: no link with the plugin on the link line`); continue; }
      if (x.state !== 'removed') violations.push(`${at}: WPIN_OUT after the link is ${x.state}, expected removed`);
      if (x.stderrExactlyLine !== true) {
        violations.push(`${at}: the linker's stderr carries the link-time line ${x.stderrLineCount ?? 0} time(s)`
          + `${x.stderrLineCount === 1 ? ' among other text' : ''}, expected exactly once and nothing else`);
      }
      if (x.asmEqualsStock !== true) violations.push(`${at}: the assembly is not byte-identical to the stock link`);
    }
  }
  if (!considered.length) return { held: false, links: 0, violations: ['vacuous: no link with the plugin on the link line'] };
  return { held: violations.length === 0, links: considered.length * 2, violations };
}

/**
 * What was at WPIN_OUT after a link with the plugin on the link line
 * (configuration ii). The probe puts SENTINEL there before the link.
 *
 *   'sentinel-kept'   the plugin's load-time callback did not run (it removes
 *                     whatever is at WPIN_OUT before anything else)
 *   'removed'         the callback ran and the pass never wrote a record (the
 *                     plugin says so on stderr: LINK_LINE_REMOVED)
 *   'record-written'  a WipePin record: the pass ran at link time
 *   'other-file'      something else is there
 */
export function linkPluginState({ exists, text }) {
  if (!exists) return 'removed';
  if (text === SENTINEL) return 'sentinel-kept';
  try {
    const r = JSON.parse(text);
    if (r && typeof r === 'object' && !Array.isArray(r) && typeof r.schemaVersion === 'string' && /^wipe-pin-/.test(r.schemaVersion)) return 'record-written';
  } catch { /* not a record */ }
  return 'other-file';
}

/**
 * Zero-fill `llvm.memset` intrinsics in the named functions of a textual IR
 * module (llvm-dis output), split by the volatile operand. Used on the
 * compile-stage bitcode to say where a loss happens: a wipe the compile stage
 * already removed never reaches the linker. `null` when none of the names is
 * defined in the module.
 */
export function zeroMemsetsInFunctions(ll, names) {
  if (typeof ll !== 'string') return null;
  const want = new Set(names);
  const out = { defined: [], volatile: 0, plain: 0 };
  let cur = null;
  for (const line of ll.split('\n')) {
    if (cur === null) {
      const m = /^define\b[^@]*@("?)([^"(\s]+)\1\(/.exec(line);
      if (m && want.has(m[2])) { cur = m[2]; out.defined.push(cur); }
      continue;
    }
    if (line === '}') { cur = null; continue; }
    const c = /\bcall void @llvm\.memset\.[\w.]+\([^,]+,\s*i8 0,.*\bi1 (true|false)\)/.exec(line);
    if (c) { if (c[1] === 'true') out.volatile++; else out.plain++; }
  }
  return out.defined.length ? out : null;
}

/**
 * The ids a probe measures at one level, from the tracked rows of one
 * compiler: the erasure files whose verdict there is WIPE_ELIMINATED, or with
 * `allRemovable` every file of the `removable` idiom there -- the eliminated
 * ones and the ones whose wipe survives, so that a run can say whether the LTO
 * link removes a wipe the non-LTO find step saw survive. `verdictField` is
 * where the rows keep the verdict: `verdict` in the find step's rows
 * (../../../ai-generated/data/r2-build-rows.json), `baseline` in the repair
 * loop's (../../data/). Sorted, each id once.
 */
export function selectErasureIds(rows, { cc, opt, allRemovable = false, verdictField = 'verdict' }) {
  if (!Array.isArray(rows)) return [];
  const pick = rows.filter((r) => r && r.kind === 'erasure' && r.cc === cc && r.opt === opt
    && (allRemovable ? r.idiom === 'removable' : r[verdictField] === ELIMINATED));
  return [...new Set(pick.map((r) => r.id))].sort();
}

/** `k` items spread evenly over `list` (order kept); the whole list when k is absent or not smaller. */
export function evenSample(list, k) {
  if (!Number.isInteger(k) || k <= 0 || k >= list.length) return [...list];
  const out = [];
  for (let i = 0; i < k; i++) out.push(list[Math.floor((i * list.length) / k)]);
  return out;
}

/**
 * Counts for one (mode, opt) group of rows. Pure; the probe prints it.
 *
 * `trackedDiff` lists the cells whose LTO baseline differs from the find step's
 * tracked, non-LTO verdict for the same (id, clang-18, opt) -- expected to be
 * possible, since the LTO backend is a second optimisation of the same code.
 */
export function summarizeGroup(rows) {
  const n = (f) => rows.filter(f).length;
  const outcomes = Object.fromEntries(LTO_OUTCOMES.map((o) => [o, n((r) => r.outcome === o)]));
  const lpLinks = rows.flatMap((r) => (r.linkPlugin ? [r.linkPlugin.w, r.linkPlugin.wo] : []));
  const detPairs = rows.flatMap((r) => (r.deterministic ? Object.values(r.deterministic) : []));
  const dryObj = rows.flatMap((r) => (r.dryObjectEqualsOff ? Object.values(r.dryObjectEqualsOff) : []));
  const dryAsm = rows.flatMap((r) => (r.dryAsmEqualsOff ? Object.values(r.dryAsmEqualsOff) : []));
  const elim = rows.filter((r) => r.outcome !== 'NOT_LTO' && r.baseline === ELIMINATED);
  return {
    cells: rows.length,
    baselineEliminated: elim.length,
    baselineSurvived: n((r) => r.outcome !== 'NOT_LTO' && r.baseline === SURVIVED),
    baselineOther: n((r) => r.outcome !== 'NOT_LTO' && r.baseline !== ELIMINATED && r.baseline !== SURVIVED),
    trackedDiff: rows.filter((r) => r.outcome !== 'NOT_LTO' && r.tracked !== r.baseline)
      .map((r) => ({ id: r.id, tracked: r.tracked, lto: r.baseline })),
    outcomes,
    dry: gradeDryRun(rows),
    linkPlugin: {
      links: lpLinks.length,
      recordWritten: lpLinks.filter((x) => x && x.state === 'record-written').length,
      callbackRan: lpLinks.filter((x) => x && (x.state === 'removed' || x.state === 'record-written')).length,
      sentinelKept: lpLinks.filter((x) => x && x.state === 'sentinel-kept').length,
      asmEqualsStock: lpLinks.filter((x) => x && x.asmEqualsStock === true).length,
      stderrExactlyLine: lpLinks.filter((x) => x && x.stderrExactlyLine === true).length,
      cells: n((r) => !!r.linkPlugin),
      verdictEqualsBaseline: n((r) => r.linkPlugin && r.linkPlugin.verdict === r.baseline),
      grade: gradeLinkPlugin(rows),
    },
    determinism: { pairs: detPairs.length, identical: detPairs.filter((x) => x === true).length },
    dryObjectEqualsOff: { of: dryObj.length, equal: dryObj.filter((x) => x === true).length },
    dryAsmEqualsOff: { of: dryAsm.length, equal: dryAsm.filter((x) => x === true).length },
    // Where the loss happens, in the baseline-eliminated cells: does the
    // compile-stage bitcode of w/off still hold a plain zero-fill memset in the
    // requested functions, and does w/on hold a volatile one?
    stage: {
      eliminated: elim.length,
      wOffBitcodeHoldsPlainMemset: elim.filter((r) => r.bitcode && r.bitcode.wOff && r.bitcode.wOff.plain > 0).length,
      wOffBitcodeHoldsNone: elim.filter((r) => r.bitcode && r.bitcode.wOff && r.bitcode.wOff.plain + r.bitcode.wOff.volatile === 0).length,
      wOnBitcodeHoldsVolatile: elim.filter((r) => r.bitcode && r.bitcode.wOn && r.bitcode.wOn.volatile > 0).length,
      unread: elim.filter((r) => !r.bitcode || !r.bitcode.wOff || !r.bitcode.wOn).length,
    },
  };
}

/** True when `path` (resolved) lies inside `repoRoot` (resolved). Pure string logic over already-resolved paths. */
export function insideRepo(resolvedPath, resolvedRepoRoot, sep = '/') {
  const a = resolvedPath.endsWith(sep) ? resolvedPath : resolvedPath + sep;
  const r = resolvedRepoRoot.endsWith(sep) ? resolvedRepoRoot : resolvedRepoRoot + sep;
  return a === r || a.startsWith(r);
}

/**
 * Which compiler a run drives, and what follows from that.
 *
 * There are two repair plugins, one per vendor, and they are not
 * interchangeable: WipePin is an LLVM pass plugin (compiler/llvm-repair/) that
 * clang loads with `-fpass-plugin=<so>`; WipePinGcc is a GCC plugin
 * (compiler/gcc-repair/) that gcc loads with `-fplugin=<so>`. Both write the
 * same `wipe-pin-v2` record, and the record says which one wrote it
 * (`component`), so the reader is told which one this run loaded.
 *
 * The vendor is decided from the basename of `--cc` and from nothing else: the
 * spelling is what the user typed, and what it names is what gets run. A
 * basename that names neither vendor is refused rather than guessed at, because
 * a guess picks the plugin flag and the record the reader will insist on.
 *
 * Also here: where a run's tracked data goes (per compiler, so two compilers can
 * never overwrite each other's file), and whether a tracked rows file is a full
 * --write-data run. All pure.
 */

/** Per vendor: the plugin that repairs it, and how the compiler is told to load it. */
export const VENDORS = Object.freeze({
  clang: Object.freeze({ component: 'WipePin', pluginFlag: '-fpass-plugin=', pluginDir: 'compiler/llvm-repair' }),
  gcc: Object.freeze({ component: 'WipePinGcc', pluginFlag: '-fplugin=', pluginDir: 'compiler/gcc-repair' }),
});

// The same spellings the runner used to refuse gcc with: `gcc`, `gcc-13`,
// `g++-13.3`, and a target-prefixed `x86_64-linux-gnu-gcc-13`. clang is spelled
// the same way.
const GCC_RE = [/^(gcc|g\+\+)(-[\d.]+)?$/, /-(gcc|g\+\+)(-[\d.]+)?$/];
const CLANG_RE = [/^(clang|clang\+\+)(-[\d.]+)?$/, /-(clang|clang\+\+)(-[\d.]+)?$/];

/**
 * 'clang', 'gcc', or null when the basename names neither. `cc` may be a path;
 * only its last component is read (both separators, so a Windows spelling reads
 * the same).
 */
export function vendorOf(cc) {
  if (typeof cc !== 'string' || !cc) return null;
  const base = cc.split(/[\\/]/).pop();
  if (GCC_RE.some((re) => re.test(base))) return 'gcc';
  if (CLANG_RE.some((re) => re.test(base))) return 'clang';
  return null;
}

/**
 * The plugin-on argument and the record component for one run.
 * @returns {{vendor: string, component: string, pluginArg: string}}
 */
export function vendorConfig(vendor, pluginPath) {
  const v = VENDORS[vendor];
  if (!v) throw new Error(`vendorConfig: unknown vendor ${JSON.stringify(vendor)}`);
  return { vendor, component: v.component, pluginArg: `${v.pluginFlag}${pluginPath}` };
}

/**
 * The tracked files a --write-data run writes, by compiler basename.
 *
 * clang-18's keep the names they were first written under,
 * `r2-repair-rows.json` and `r2-repair-results.txt`, so the existing tracked
 * data and every reference to it stay valid. Every other compiler gets its
 * basename as a suffix (`r2-repair-rows-gcc-13.json`): a name that says whose
 * rows these are, and that no second compiler can write over.
 */
export const LEGACY_CC = 'clang-18';
export function dataFileNames(ccName) {
  if (ccName === LEGACY_CC) return { rows: 'r2-repair-rows.json', results: 'r2-repair-results.txt' };
  if (typeof ccName !== 'string' || !/^[A-Za-z0-9_.+-]+$/.test(ccName)) {
    throw new Error(`dataFileNames: ${JSON.stringify(ccName)} is not a compiler basename`);
  }
  return { rows: `r2-repair-rows-${ccName}.json`, results: `r2-repair-results-${ccName}.txt` };
}

/**
 * The value of `_FORTIFY_SOURCE` in a `-dM -E` listing of predefined macros,
 * exactly as the listing spells it ('3'; '' for a definition with no value), or
 * null when the listing does not define it.
 *
 * Measured, per run and level, because the two vendors differ and the shared
 * FLAGS do not equalise it: Ubuntu's gcc-13 predefines `_FORTIFY_SOURCE=3`
 * whenever it optimises, and clang-18 does not predefine it at all. So every
 * gcc cell at -O1 and above is built with glibc's fortifying headers, where a
 * `memset` in the source is a call to the header's gnu_inline wrapper
 * (compiler/gcc-repair/README.md). The run says so rather than assuming it.
 */
export function fortifyFromDefines(text) {
  if (typeof text !== 'string') return null;
  const m = /^#define[ \t]+_FORTIFY_SOURCE(?:[ \t]+([^\r\n]*?))?[ \t]*\r?$/m.exec(text);
  if (!m) return null;
  return m[1] ?? '';
}

/**
 * Is `rows` what a full --write-data run for `cc` writes? --write-data is
 * refused for red controls, subsets, partial levels, module scope and plans, so
 * a file written by it passes every check below; a file that fails one was put
 * there some other way, and its counts cover less than they appear to.
 *
 *   - every row names `cc`, and no other compiler
 *   - every erasure and no-wipe row is functions scope, no dry run, no target suffix
 *   - every id in `erasureIds` (every erasure-family file of the corpus) has a
 *     row, erasure or no-wipe, at every level of `allOpts`
 *
 * @returns {{full: boolean, why: string[]}}  `why` names each failed check, briefly
 */
export function fullRunCheck(rows, { cc, allOpts, erasureIds }) {
  const why = [];
  if (!Array.isArray(rows)) return { full: false, why: ['not a list of rows'] };
  const cellRows = rows.filter((r) => r && (r.kind === 'erasure' || r.kind === 'none'));
  const otherCc = [...new Set(rows.filter((r) => r && r.cc !== undefined && r.cc !== cc).map((r) => r.cc))].sort();
  if (otherCc.length) why.push(`rows for ${otherCc.join(', ')}, not only ${cc}`);
  if (cellRows.some((r) => r.scope !== 'functions')) why.push('a row not in functions scope');
  if (cellRows.some((r) => r.dryRun !== false)) why.push('a dry-run row');
  if (cellRows.some((r) => r.targetSuffix !== null)) why.push('a row with a target suffix');
  const have = new Set(cellRows.map((r) => `${r.id}|${r.opt}`));
  let missing = 0;
  for (const id of erasureIds) for (const o of allOpts) if (!have.has(`${id}|${o}`)) missing++;
  if (missing) why.push(`${missing} (file, level) cell(s) of the corpus have no row`);
  if (!cellRows.length) why.push('no erasure or no-wipe rows');
  return { full: why.length === 0, why };
}

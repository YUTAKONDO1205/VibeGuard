// Path and line normalisation — the layer at which two tools either name the
// same place or silently fail to.
//
// ★★ WHY A NORMALISER LIVES HERE AT ALL, WHEN THE REPO HAS ONE
//
// `packages/analysis-graph/src/dependency-graph/index.ts` exports
// `normalizePath` with exactly the semantics below, and the first instinct — and
// this project's own standing rule against divergent copies — says import it.
// That was rejected for one reason: `@vibeguard/analysis-graph` depends on
// `@vibeguard/rules`, `@vibeguard/analyzer-core` and `@vibeguard/findings-schema`,
// and pulling the entire cross-file analysis engine into a report parser to reach
// a fourteen-line pure function inverts the dependency direction (an adapter
// would depend on an analysis package that has no idea adapters exist) and makes
// this package unusable in any context where the graph is not wanted.
//
// The copy is therefore deliberate, and it is DEFENDED rather than trusted: the
// implementation below is character-for-character the one in dependency-graph,
// and `parser-parity.test.ts` proves it is semantically identical to what
// `scripts/sec-transfer-semgrep.mjs` computes, which is the normaliser the
// comparison actually has to agree with. A copy nobody checks is the failure this
// project has already paid for once; a copy with a proof is a copy.
//
// ★★ AND WHY THE TWO EXISTING PARSERS ALREADY DISAGREE
//
// This is a real, reproducible divergence in the repository as it stands, found
// while writing this file, and it is the reason `rootDir` exists:
//
//   input                                    sec-transfer-semgrep.mjs   sast-baseline-eval.mjs
//   samples\vulnerable\a.py                  samples/vulnerable/a.py    samples/vulnerable/a.py   agree
//   ./samples/a.py                           samples/a.py               samples/a.py              agree
//   samples//a.py                            samples/a.py               samples//a.py             DIFFER
//   samples/x/../a.py                        samples/a.py               samples/x/../a.py         DIFFER
//   C:\repo\samples\a.py  (cwd = C:\repo)    samples/a.py               C:/repo/samples/a.py      DIFFER
//
// `sec-transfer-semgrep.mjs` normalises with `relative(REPO_ROOT, resolve(REPO_ROOT, p))`,
// which collapses `.`, `..` and repeated separators AND reduces absolute paths
// against the process cwd. `sast-baseline-eval.mjs` only swaps separators and
// strips a leading `./`. On the recorded Semgrep artifacts both scripts were
// written against — which contain only clean relative paths — the two agree
// exactly, which is why the divergence has never bitten.
//
// This package takes the sec-transfer semantics for the parts that are
// unambiguously right (collapse `.`, `..`, `//`, backslashes) and makes the part
// that is NOT unambiguously right (reducing an absolute path against a directory)
// an explicit opt-in, because a user-supplied report may have been produced from
// any working directory and this package has no way to know which. Guessing
// `process.cwd()` on the user's behalf is how a path silently becomes wrong.

/**
 * Collapse a path to the repo's canonical form: forward slashes, no `.`
 * segments, `..` resolved where it can be, no empty segments.
 *
 * ★ CHARACTER-FOR-CHARACTER THE `normalizePath` OF
 * packages/analysis-graph/src/dependency-graph/index.ts. Do not "improve" it in
 * one place. A leading `..` that cannot be resolved is KEPT (`../outside/a.ts`
 * stays as it is) rather than dropped, because dropping it would silently move a
 * path from outside the tree to inside it.
 */
export function normalizePath(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  const out: string[] = [];
  for (const part of parts) {
    if (part === '' && out.length > 0) continue;
    if (part === '.') continue;
    if (part === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
      continue;
    }
    out.push(part);
  }
  return out.join('/');
}

/**
 * Whether a path is absolute in either POSIX or Windows form.
 *
 * Both forms are recognised regardless of the platform this runs on, and that is
 * required rather than defensive: the recorded Semgrep artifact in this package's
 * fixtures was produced on Windows and a CI run of the same tool produces POSIX
 * paths for the same repository. A report is a portable artifact — it can be
 * generated on one machine and merged on another — so a platform-conditional
 * answer here would make the merge depend on where it happened to run.
 *
 * UNC paths (`\\server\share`) normalise to `//server/share` and are absolute.
 */
export function isAbsolutePath(p: string): boolean {
  const slashed = p.replace(/\\/g, '/');
  return slashed.startsWith('/') || /^[A-Za-z]:\//.test(slashed);
}

/**
 * Normalise a path out of a report, optionally reducing it against `rootDir`.
 *
 * With no `rootDir`, separators and segments are canonicalised and nothing else —
 * an absolute path stays absolute. With a `rootDir`, an absolute path that lies
 * under it becomes relative to it, reproducing what `sec-transfer-semgrep.mjs`
 * computes.
 *
 * ★ AN ABSOLUTE PATH THAT DOES NOT LIE UNDER `rootDir` IS LEFT ABSOLUTE, rather
 * than being expressed as a chain of `../`. `relative()` would happily produce
 * `../../../etc/passwd` for a report naming a file outside the project, and that
 * string looks like a project-relative path to every consumer downstream — it
 * would sort next to real findings and join against them. Leaving it absolute
 * keeps "this is not in your repository" visible, at the cost of never matching a
 * VibeGuard finding, which is correct: VibeGuard did not scan it.
 *
 * Case is NOT folded, on any platform. Windows paths are case-insensitive and
 * folding would make `SRC/app.ts` and `src/app.ts` join — but folding would also
 * merge two genuinely distinct files on the Linux CI runner where the same repo
 * is scanned, and a join that is correct on one platform and wrong on another is
 * worse than one that is conservative on both.
 */
export function normalizeReportPath(raw: string, rootDir?: string): string {
  const normalized = normalizePath(raw);
  if (rootDir === undefined || rootDir === '') return normalized;
  if (!isAbsolutePath(normalized)) return normalized;
  const root = normalizePath(rootDir).replace(/\/+$/, '');
  if (root === '') return normalized;
  if (normalized === root) return '';
  if (normalized.startsWith(`${root}/`)) return normalized.slice(root.length + 1);
  return normalized;
}

/**
 * How many lines apart two tools may place the same weakness and still be talking
 * about it.
 *
 * ★ TWO, TAKEN FROM THE TWO EXISTING COMPARISONS RATHER THAN CHOSEN HERE.
 * `scripts/sec-transfer-semgrep.mjs` uses `LINE_TOLERANCE = 2`;
 * `scripts/sast-baseline-eval.mjs` uses `LINE_TOL = 2` and calls a pair within it
 * "co-located". Picking a third number would mean this package answered "did the
 * two tools agree" differently from the two artifacts the project already
 * publishes.
 *
 * Why any tolerance is needed: tools anchor a finding at different tokens of the
 * same statement. On `samples/vulnerable/sql_injection.py` Semgrep anchors
 * `sqlalchemy-execute-raw-query` at the `execute(` call; a dataflow tool
 * typically anchors at the argument expression, which may be the next line in a
 * wrapped call. Zero tolerance would report those as two separate findings by two
 * tools that in fact agree.
 *
 * Why it is small: at a tolerance of, say, 10, two unrelated findings in the same
 * dense function join, and a join is unrecoverable — once merged, no downstream
 * consumer can tell that two weaknesses were folded into one. The asymmetry
 * favours the small number: a missed join shows up as two rows a reader can see,
 * a false join shows up as nothing at all.
 */
export const DEFAULT_LINE_TOLERANCE = 2;

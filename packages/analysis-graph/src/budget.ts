// Budget control for cross-file analysis.
//
// WHY A SECOND BUDGET SYSTEM EXISTS
//
// `@vibeguard/rules` already bounds work: `REGEX_INPUT_CAP` truncates a long
// file, `REGEX_DEADLINE_MS` cuts off a slow rule, `REGEX_MATCH_LIMIT` caps
// matches. Those are the D3 bounds and they are per-FILE, because the core
// engine's unit of work is a file. Cross-file analysis reads the whole project
// before any rule runs, so its unbounded dimension is one the D3 bounds cannot
// see: a repository with 200,000 files stays inside every per-file bound and
// still never finishes. The dimension has to be bounded where it exists.
//
// THE SHAPE OF THE BOUND: DEGRADE, NEVER THROW
//
// Copied deliberately from how D3 behaves, because the alternative was already
// found to be wrong once here. A scan that hits a bound returns PARTIAL results
// and says so; it does not fail. Throwing would turn "this repo is large" into
// "VibeGuard is broken", and the predictable response to a tool that crashes on
// big repositories is to stop running it — which removes far more security
// signal than the truncation did. Silence is the other failure and is worse: a
// partial scan that looks identical to a clean one is a scan that reports
// "no findings" for a project it never opened.
//
// DETERMINISM IS PART OF THE BOUND
//
// When a cap drops files, WHICH files get dropped must not vary between runs.
// A non-deterministic admission set produces findings that appear and disappear
// across otherwise identical scans, which destroys the baseline workflow the
// whole design-smell feature is meant to support (a reviewer must be able to say
// "this is new since main"). Admission is therefore in sorted path order, with
// no tie-breaking on anything the filesystem chooses.

import type { GraphBudget, GraphDegradation } from './types.js';

/**
 * Maximum number of source files admitted to the graph.
 *
 * Set where it is because it is comfortably above real single-service
 * repositories (the projects a design smell about scattered authorization is a
 * statement about) and comfortably below monorepos where a whole-project graph
 * was never the right unit anyway. A user past this limit is better served by
 * scanning a subdirectory, and the degradation message says so.
 */
export const GRAPH_FILE_LIMIT = 2_000;

/**
 * Maximum total bytes of source admitted.
 *
 * A second, independent dimension rather than a refinement of the file limit:
 * 2,000 files of 20KB and 20 files of 2MB are the same amount of work and only
 * one of them is caught by a file count. Generated bundles and vendored
 * dependencies are the usual way a repository is mostly bytes and barely files.
 */
export const GRAPH_TOTAL_BYTES_CAP = 20 * 1024 * 1024;

/**
 * Wall-clock budget for the whole cross-file pass.
 *
 * Checked COOPERATIVELY at phase boundaries (after indexing, after graph build,
 * between rules) rather than preemptively inside loops. Preemption would need
 * the check in the hot path of every scanner, where it costs more than the work
 * it guards; phase granularity is coarse enough that a single pathological file
 * can overshoot, which is what the per-file D3 bounds are already there to
 * prevent. The two bounds compose: D3 keeps any one file bounded, this keeps the
 * count of files bounded.
 */
export const GRAPH_DEADLINE_MS = 10_000;

export interface CreateBudgetOptions {
  fileLimit?: number;
  totalBytesCap?: number;
  deadlineMs?: number;
  /**
   * Injected clock. Exists so tests can drive the deadline without sleeping;
   * production callers omit it and get `Date.now`.
   */
  now?: () => number;
}

/**
 * Decide which files the graph is allowed to read.
 *
 * Takes paths and sizes rather than contents, so the caller can apply the caps
 * BEFORE reading 20MB off disk — a cap that only triggers after the read has
 * already happened bounds memory but not I/O, which is the expensive half.
 *
 * Returns the admitted subset in sorted order. Sorting is `localeCompare`-free
 * on purpose: plain lexicographic byte order is stable across locales, and a
 * cap whose membership depended on the machine's locale would be exactly the
 * non-determinism this is written to avoid.
 */
export function admitFiles(
  candidates: { filePath: string; size: number }[],
  budget: GraphBudget,
  options: CreateBudgetOptions = {},
): string[] {
  const fileLimit = options.fileLimit ?? GRAPH_FILE_LIMIT;
  const bytesCap = options.totalBytesCap ?? GRAPH_TOTAL_BYTES_CAP;

  const sorted = [...candidates].sort((a, b) => (a.filePath < b.filePath ? -1 : a.filePath > b.filePath ? 1 : 0));

  const admitted: string[] = [];
  let bytes = 0;
  let hitBytes = false;

  for (const c of sorted) {
    if (admitted.length >= fileLimit) break;
    if (bytes + c.size > bytesCap) {
      // Skip rather than stop: a single oversized vendored bundle in the middle
      // of the tree must not silently truncate every file that sorts after it.
      hitBytes = true;
      continue;
    }
    admitted.push(c.filePath);
    bytes += c.size;
  }

  if (sorted.length > fileLimit) {
    budget.report({
      kind: 'file-limit',
      detail:
        `Cross-file analysis read the first ${fileLimit} of ${sorted.length} source files ` +
        `(sorted by path) and stopped. Results are PARTIAL: a design smell whose evidence ` +
        `lies wholly in the unread files was not reported. Scan a subdirectory to analyse ` +
        `the remainder.`,
      admittedFiles: admitted.length,
      totalFiles: sorted.length,
    });
  }
  if (hitBytes) {
    budget.report({
      kind: 'byte-cap',
      detail:
        `Cross-file analysis skipped files that would exceed the ${Math.round(bytesCap / 1024 / 1024)}MB ` +
        `source budget. Results are PARTIAL: the skipped files contributed no symbols, ` +
        `imports, or routes to the graph.`,
      admittedFiles: admitted.length,
      totalFiles: sorted.length,
    });
  }

  return admitted;
}

/**
 * Create a budget tracker.
 *
 * `report` is idempotent PER KIND, not per call: hitting the byte cap on eleven
 * files is one fact about the scan, and eleven identical degradation lines would
 * bury the one line the reader needs. The first report of a kind wins, so the
 * counts it carries are the ones from the moment the bound first bit.
 */
export function createBudget(options: CreateBudgetOptions = {}): GraphBudget {
  const now = options.now ?? (() => Date.now());
  const deadlineMs = options.deadlineMs ?? GRAPH_DEADLINE_MS;
  const start = now();
  const seen = new Map<GraphDegradation['kind'], GraphDegradation>();

  return {
    expired(): boolean {
      const over = now() - start >= deadlineMs;
      if (over && !seen.has('graph-deadline')) {
        seen.set('graph-deadline', {
          kind: 'graph-deadline',
          detail:
            `Cross-file analysis passed its ${deadlineMs}ms budget and stopped at a phase ` +
            `boundary. Results are PARTIAL: analysis phases after the cut-off did not run, ` +
            `so findings they would have produced are absent rather than absent-and-clean.`,
        });
      }
      return over;
    },
    report(d: GraphDegradation): void {
      if (!seen.has(d.kind)) seen.set(d.kind, d);
    },
    degradations(): GraphDegradation[] {
      // Fixed order rather than insertion order, so two runs that hit the same
      // bounds in a different sequence still serialise identically.
      const order: GraphDegradation['kind'][] = ['file-limit', 'byte-cap', 'graph-deadline'];
      return order.filter((k) => seen.has(k)).map((k) => seen.get(k)!);
    },
  };
}

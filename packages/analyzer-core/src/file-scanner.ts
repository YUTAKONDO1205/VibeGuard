import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  emptySummary,
  summarize,
  compareSeverity,
  type Finding,
  type RuleError,
  type ScanDegradation,
  type ScanMode,
  type ScanResponse,
  type DeclaredPackageVetoRecord,
  type UnexaminedInput,
} from '@vibeguard/findings-schema';
import { Analyzer, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
import { detectLanguageFromPath } from './language-detect.js';
import { evaluatePathSuppression, suppressionsForPath, type VibeguardConfig } from './config.js';
import { collectSuppressions, mergeSuppressions, tallySuppression, type SuppressionTally } from './suppress.js';
import { loadConfig } from './config-loader.js';

export const DEFAULT_IGNORE = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.turbo',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.idea',
  '.vscode',
]);

/**
 * Largest single file a directory scan will open. Larger ones are skipped.
 *
 * Exported because it is a shared admission rule, not a private detail. The
 * cross-file pass in `@vibeguard/analysis-graph` walks the SAME target and its
 * findings land in the SAME report, so if the two disagree about which files
 * exist, a cross-file finding can cite a file the per-file scan never opened.
 * That is exactly what happened while this was private and the graph carried
 * its own `1024 * 1024` under a comment claiming to mirror it: every file
 * between 1,000,000 and 1,048,576 bytes was admitted by one pass and silently
 * dropped by the other.
 *
 * Decimal MB rather than MiB is arbitrary but it is the number that shipped, so
 * it is the one both passes now read.
 */
export const MAX_FILE_BYTES = 1_000_000;

/**
 * Directory names on `DEFAULT_IGNORE` that hold what a project SHIPS rather
 * than what it depends on.
 *
 * The distinction is the whole point of reporting skips at all. Skipping
 * `node_modules` is housekeeping and nobody needs telling. Skipping `dist` is
 * skipping the only artifact the user's visitors will ever execute, and until
 * `unexamined` existed the scan said the same thing about both: nothing.
 *
 * Membership here does NOT change what is skipped. It changes how loudly the
 * skip is reported.
 */
const BUILD_OUTPUT_DIRS = new Set(['dist', 'build', 'out', '.next', '.turbo']);

/** A path the walk declined to descend into or read, with the reason. */
interface SkipRecord {
  kind: UnexaminedInput['kind'];
  /** Absolute path, converted to a target-relative one by the caller. */
  full: string;
  looksLikeBuildOutput: boolean;
  bytes?: number;
}

async function* walk(
  dir: string,
  ignore: Set<string>,
  skips: SkipRecord[],
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    // Was a bare `return`, which is the same silence this whole channel exists
    // to remove — and worse than the size skip it sits next to, because a
    // directory that cannot be read hides an unknown NUMBER of files rather
    // than one known file.
    skips.push({ kind: 'unreadable', full: dir, looksLikeBuildOutput: false });
    return;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) {
      // Only directories are recorded. An ignore entry that matched a file is
      // a configuration choice about one file; an ignored directory is an
      // unknown quantity of unread input, which is the thing worth saying.
      if (entry.isDirectory()) {
        skips.push({
          kind: 'ignored-directory',
          full: join(dir, entry.name),
          looksLikeBuildOutput: BUILD_OUTPUT_DIRS.has(entry.name),
        });
      }
      continue;
    }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full, ignore, skips);
    } else if (entry.isFile()) {
      yield full;
    } else {
      // ── NEITHER A FILE NOR A DIRECTORY ─────────────────────────────────────
      //
      // A symlink, a Windows junction, a socket, a device. `readdir` with
      // `withFileTypes` does NOT follow links, so a symlinked source directory
      // — the ordinary shape of a pnpm store, an Nx or Turborepo output, a
      // `deploy` tree — reports as `isSymbolicLink()` and fell through both
      // branches into nothing. Not scanned, and not mentioned.
      //
      // Still not followed: resolving links would need cycle detection and
      // would let a scan wander outside the target the user named. What changes
      // is that declining to follow one is now something the report says.
      skips.push({
        kind: entry.isSymbolicLink() ? 'link-not-followed' : 'unreadable',
        full,
        looksLikeBuildOutput: BUILD_OUTPUT_DIRS.has(entry.name) || looksLikeBuildArtifact(full),
      });
    }
  }
}

export interface ScanPathOptions extends AnalyzerOptions {
  mode?: ScanMode;
  includeRemediation?: boolean;
  /** Extra directory names to ignore on top of the defaults. */
  ignore?: string[];
  /** When true, only scan files whose extension maps to a known language. */
  knownLanguagesOnly?: boolean;
  /** Optional reporter invoked for each file scanned. */
  onFile?: (filePath: string) => void;
  /**
   * Explicit config file path. When omitted, scanPath auto-discovers
   * `.vibeguardrc.json` / `vibeguard.config.json` in the scan target's
   * directory. Pass `false` to skip discovery entirely.
   */
  config?: string | false;
  /** Override "now" when evaluating config `expires` dates. Primarily for tests. */
  now?: Date;
}

/**
 * §17z-b — how the declared-package veto reaches a directory walk.
 *
 * Inherited from `AnalyzerOptions` rather than declared here, and set on the
 * request of every file rather than only on the Analyzer, so the value that
 * ends up in effect is visible at the call site instead of hidden in a
 * constructor two files away. Same list for the whole walk: the evidence is the
 * scan target's lockfile, which is a statement about the project, not about a
 * file. A monorepo whose sub-packages each carry their own lockfile therefore
 * gets the ROOT one applied everywhere (or none, if the root has none) —
 * accepted, because the alternative is a per-directory lockfile search whose
 * behaviour nobody can predict from the command line they typed. Scanning a
 * sub-package directly gives it its own lockfile, which is the escape hatch.
 */


export async function scanPath(target: string, options: ScanPathOptions = {}): Promise<ScanResponse> {
  const start = Date.now();
  const ignore = new Set([...DEFAULT_IGNORE, ...(options.ignore ?? [])]);
  const analyzer = new Analyzer(options);
  const findings: Finding[] = [];
  // Deduped by ruleId: a rule that throws on every file would otherwise appear
  // once per file. Keep the first message. Without this, a rule crash is visible
  // in a single-snippet `Analyzer.scan` but silently lost across a directory scan.
  const ruleErrorsByRule = new Map<string, RuleError>();
  const degradationsByFileKind = new Map<string, ScanDegradation>();
  // Aggregated across files for the same reason the suppression tally is: a
  // channel that DELETES findings has to be visible in the artifact, not only
  // on the CLI's stderr. Keyed rule|package|file, so a project depending on a
  // dozen near-miss names gets a dozen lines and not one per match.
  const vetoesByKey = new Map<string, DeclaredPackageVetoRecord>();
  // Whether the veto was ARMED, which is a different fact from whether it
  // fired. `Analyzer.scan` marks it by emitting `declaredPackageVetoes` at all
  // — `[]` when it ran and removed nothing — so this flag is read off the
  // per-file responses rather than recomputed from `options.declaredPackages`.
  // Recomputing would drift: a declared list of nothing but blanks builds no
  // index, and the aggregate would then claim a veto ran that never did.
  let vetoArmed = false;
  // D8: both suppression channels land in one tally. The analyzer reports the
  // pragma half per file (and that per-file response is otherwise discarded
  // here), the loop below adds the config half.
  const suppressionTally: SuppressionTally = new Map();
  const now = options.now ?? new Date();

  const stats = await stat(target);
  const files: string[] = [];
  // Collected during the walk and while reading, then turned into
  // `unexamined` at the end. A scan that opened nothing it was asked to open
  // has to be able to say so; see `ScanResponse.unexamined`.
  const skips: SkipRecord[] = [];
  if (stats.isFile()) {
    files.push(target);
  } else {
    for await (const file of walk(target, ignore, skips)) {
      files.push(file);
    }
  }

  let config: VibeguardConfig | undefined;
  if (options.config !== false) {
    const configDir = stats.isFile() ? dirname(resolve(target)) : resolve(target);
    const explicit = options.config
      ? isAbsolute(options.config)
        ? options.config
        : resolve(options.config)
      : undefined;
    const loaded = await loadConfig(configDir, explicit);
    config = loaded?.config;
  }

  for (const file of files) {
    options.onFile?.(file);
    const language = detectLanguageFromPath(file);
    if (options.knownLanguagesOnly && !language) continue;
    let info;
    try {
      info = await stat(file);
    } catch {
      skips.push({ kind: 'unreadable', full: file, looksLikeBuildOutput: false });
      continue;
    }
    if (info.size > MAX_FILE_BYTES) {
      // Was a bare `continue`. The cap stays exactly where it was — what
      // changes is that the drop leaves a trace. A production bundle is
      // routinely several MB, so this branch is not an edge case for the
      // projects this tool exists to protect: it is the common case, and it
      // was silent.
      skips.push({
        kind: 'over-size-limit',
        full: file,
        looksLikeBuildOutput: looksLikeBuildArtifact(file),
        bytes: info.size,
      });
      continue;
    }
    let content: string;
    try {
      content = await readFile(file, 'utf8');
    } catch {
      skips.push({ kind: 'unreadable', full: file, looksLikeBuildOutput: false });
      continue;
    }
    const relPath = stats.isFile() ? file : relative(target, file).split(sep).join('/');
    const result = analyzer.scan({
      targetType: 'file',
      filePath: relPath,
      content,
      language,
      mode: options.mode ?? 'standard',
      includeRemediation: options.includeRemediation,
      ...(options.declaredPackages ? { declaredPackages: options.declaredPackages } : {}),
    });
    const pathSuppressed = suppressionsForPath(config, relPath, now);
    for (const f of result.findings) {
      // A config wildcard that the severity gate refused keeps the finding and
      // records the refusal on it, exactly like the pragma channel does inside
      // the analyzer. Note the pragma channel may already have marked this
      // finding; the config refusal does not overwrite that — one mark is the
      // signal, and the earlier one is the more specific of the two.
      const decision = evaluatePathSuppression(pathSuppressed, f.ruleId, f.severity);
      if (decision.suppressed) {
        // D8, config half. Not a defence — the finding is dropped exactly as
        // before — but the drop is now counted. `scope` is `path` unconditionally
        // because that is the only scope the config channel has (`suppress[].paths`).
        tallySuppression(suppressionTally, {
          channel: 'config',
          scope: 'path',
          ruleId: f.ruleId,
          filePath: f.filePath ?? relPath,
        });
        continue;
      }
      findings.push(
        decision.overridden && !f.suppressionOverridden
          ? { ...f, suppressionOverridden: decision.overridden }
          : f,
      );
    }
    // The pragma-channel tally from inside the analyzer. Merged, never
    // overwritten: these are counts, and two files suppressing the same rule are
    // two suppressions.
    mergeSuppressions(suppressionTally, result.suppressions);
    if (result.declaredPackageVetoes !== undefined) vetoArmed = true;
    for (const v of result.declaredPackageVetoes ?? []) {
      const k = `${v.ruleId}|${v.packageName}|${v.filePath ?? relPath}`;
      const prev = vetoesByKey.get(k);
      if (prev) prev.count += v.count;
      else vetoesByKey.set(k, { ...v, filePath: v.filePath ?? relPath });
    }
    for (const e of result.ruleErrors ?? []) {
      if (!ruleErrorsByRule.has(e.ruleId)) ruleErrorsByRule.set(e.ruleId, e);
    }
    // Degradations must survive the directory walk or the whole D3 observability
    // path is dead on the channel that matters most: the CLI and the GitHub
    // Action both come through here, so dropping them meant a 66 KB file was
    // reported as "1 finding" with no hint that 16 KB of it was never scanned —
    // exactly the "partial scan reads as clean" failure the bounds exist to
    // prevent.
    //
    // Keyed by FILE + KIND, not by rule. One oversized file trips the bound in
    // every rule that looks at it (54 of them, measured), and 54 identical lines
    // would bury the signal they exist to raise. One line per file per kind says
    // everything the reader needs: which file was cut short, and how.
    for (const d of result.degradations ?? []) {
      const key = `${d.filePath ?? relPath}::${d.kind}`;
      if (!degradationsByFileKind.has(key)) {
        degradationsByFileKind.set(key, { ...d, filePath: d.filePath ?? relPath });
      }
    }
  }

  findings.sort((a, b) => {
    const sev = compareSeverity(a.severity, b.severity);
    if (sev !== 0) return sev;
    const fileA = a.filePath ?? '';
    const fileB = b.filePath ?? '';
    if (fileA !== fileB) return fileA.localeCompare(fileB);
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });

  return {
    summary: findings.length ? summarize(findings) : emptySummary(),
    findings,
    executionTimeMs: Date.now() - start,
    engineVersions: { core: ENGINE_VERSION },
    generatedAt: new Date().toISOString(),
    ...(ruleErrorsByRule.size ? { ruleErrors: [...ruleErrorsByRule.values()] } : {}),
    ...(degradationsByFileKind.size ? { degradations: [...degradationsByFileKind.values()] } : {}),
    ...(suppressionTally.size ? { suppressions: collectSuppressions(suppressionTally) } : {}),
    // Same three-state contract the per-file response carries (see
    // `analyzer.ts`): absent = the veto never ran, `[]` = it ran over these
    // files and removed nothing, non-empty = it removed these. A directory scan
    // is the artifact the GitHub Action uploads, so it is the last place where
    // "nobody checked your lockfile" should be indistinguishable from "your
    // lockfile refuted nothing".
    ...(vetoesByKey.size
      ? { declaredPackageVetoes: [...vetoesByKey.values()] }
      : vetoArmed
        ? { declaredPackageVetoes: [] }
        : {}),
    ...(skips.length
      ? {
          unexamined: skips
            .map((s) => toUnexamined(s, target, stats.isFile()))
            // Build output first: it is the only kind whose omission changes
            // what a green tick means.
            .sort((a, b) =>
              a.looksLikeBuildOutput === b.looksLikeBuildOutput
                ? a.path.localeCompare(b.path)
                : a.looksLikeBuildOutput
                  ? -1
                  : 1,
            ),
        }
      : {}),
  };
}

/**
 * Whether a path that was dropped for size is plausibly a build artifact.
 *
 * Deliberately weak — it reads the path, nothing else — and it must stay weak,
 * because it is a sort key and a sentence, never an admission decision. A false
 * positive here promotes an ordinary large file up the list; a false negative
 * leaves a bundle further down a list it is still on. Neither hides anything,
 * which is the only property this predicate needs.
 */
function looksLikeBuildArtifact(file: string): boolean {
  const parts = file.split(sep);
  if (parts.some((p) => BUILD_OUTPUT_DIRS.has(p))) return true;
  const base = parts[parts.length - 1] ?? '';
  return /\.(?:min\.js|min\.css|bundle\.js|js\.map|css\.map)$/i.test(base);
}

function toUnexamined(s: SkipRecord, target: string, targetIsFile: boolean): UnexaminedInput {
  const path = targetIsFile ? s.full : relative(target, s.full).split(sep).join('/');
  const detail =
    s.kind === 'ignored-directory'
      ? s.looksLikeBuildOutput
        ? `${path}/ was not scanned: it is on the default ignore list. It holds build output, so no finding in this report is a statement about the code this project ships.`
        : `${path}/ was not scanned: it is on the default ignore list.`
      : s.kind === 'over-size-limit'
        ? `${path} was not scanned: ${s.bytes} bytes exceeds the ${MAX_FILE_BYTES}-byte limit. It was dropped, not cleared.`
        : s.kind === 'link-not-followed'
          ? `${path} is a link and was not followed, so whatever it points at was not scanned.`
          : `${path} could not be read and was skipped.`;
  return {
    kind: s.kind,
    path,
    looksLikeBuildOutput: s.looksLikeBuildOutput,
    ...(s.bytes === undefined ? {} : { bytes: s.bytes }),
    detail,
  };
}

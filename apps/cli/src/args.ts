import type { Confidence, ScanMode } from '@vibeguard/findings-schema';

export interface CliArgs {
  target: string;
  format: 'human' | 'json' | 'sarif' | 'markdown';
  outFile?: string;
  mode: ScanMode;
  failOn: 'critical' | 'high' | 'medium' | 'low' | 'never';
  /**
   * Drop findings below this confidence before reporting and exit-code
   * evaluation. Undefined (the default) skips filtering entirely, so output is
   * unchanged when the flag is absent.
   */
  minConfidence?: Confidence;
  /**
   * Apply deterministic auto-fixes to the scanned files on disk. Off by default.
   * Only findings whose rule carries a fixer that proves a correct edit from the
   * file bytes are touched; everything else is reported as still-manual.
   */
  fix: boolean;
  /**
   * Compute and print the fix plan (a diff of what --fix would change) without
   * writing anything. Implies fix mode; when combined with --fix, nothing is
   * written.
   */
  dryRun: boolean;
  noColor: boolean;
  noRemediation: boolean;
  knownLanguagesOnly: boolean;
  ignore: string[];
  /** Git revision range; when set, scan only added lines in `git diff <range>`. */
  diff?: string;
  /** Explicit path to a vibeguard config file. When omitted, auto-discovers in the target dir. */
  config?: string;
  /** Skip config auto-discovery entirely. */
  noConfig: boolean;
  /**
   * Run the cross-file design-smell pass (`@vibeguard/analysis-graph`) in
   * addition to the per-file rules. Off by default.
   *
   * DEFAULT-OFF IS A CONTRACT, NOT A PREFERENCE. Three regression harnesses pin
   * the output of a plain scan — `samples/vulnerable` at 51 findings,
   * `samples/safe` at 0, and the E6 confidence distribution — and every one of
   * them invokes the CLI with no flags. If cross-file analysis ran by default,
   * turning it on would be indistinguishable from breaking them, and the project
   * would lose the fixed points it uses to detect real regressions.
   *
   * It is also the honest default for a different reason: this pass reads every
   * source file in the target, which is a different cost profile from the
   * per-file scan and a surprise if it happens without being asked for.
   */
  includeDesignSmells: boolean;
  showHelp: boolean;
  showVersion: boolean;
}

const HELP = `vibeguard - security diagnostics for AI-generated code

Usage:
  vibeguard <path> [options]

Options:
  --format <human|json|sarif|markdown>
                                Output format (default: human)
  --out <file>                  Write output to file instead of stdout
  --mode <fast|standard|deep>   Scan depth (default: standard)
  --fail-on <level>             Exit non-zero when a finding meets this severity (default: high).
                                One of: critical, high, medium, low, never
  --min-confidence <level>      Hide findings below this confidence (default: show all).
                                One of: high, medium, low
                                Hidden findings are excluded from --fail-on too.
  --fix                         Apply deterministic auto-fixes to the files on disk.
                                Only rules with a provably-correct fixer are touched;
                                each applied edit is labelled safe or needs-review.
  --dry-run                     Print the fix plan (a diff of what --fix would change)
                                without writing anything. Implies fix mode.
  --ignore <name>               Extra directory name to ignore (repeatable)
  --diff <range>                Scan only lines added in \`git diff <range>\`
                                (e.g. main...HEAD, origin/main..., HEAD~3..HEAD)
  --include-design-smells       Also run cross-file design-smell analysis over the whole
                                target (VG-SMELL-*). Reads every source file in the tree,
                                so it costs more than the default per-file scan.
                                CLI and GitHub Action only — not available in the editor
                                or browser extensions.
  --known-only                  Only scan files whose extension maps to a known language
  --config <path>               Path to a vibeguard config file (.vibeguardrc.json)
                                When omitted, the file is auto-discovered in the scan target.
  --no-config                   Skip config file auto-discovery
  --no-remediation              Skip remediation generation
  --no-color                    Disable ANSI colours
  -h, --help                    Show this help
  -v, --version                 Print version

Examples:
  vibeguard ./src
  vibeguard ./src --format sarif --out report.sarif
  vibeguard suspicious.py --fail-on critical
  vibeguard ./src --min-confidence medium
  vibeguard . --diff origin/main...HEAD --format markdown
  vibeguard ./firmware --dry-run
  vibeguard ./firmware --fix
  vibeguard ./src --include-design-smells
`;

export function parseArgs(argv: string[]): CliArgs | { help: true } | { version: true } | { error: string } {
  const args: CliArgs = {
    target: '',
    format: 'human',
    mode: 'standard',
    failOn: 'high',
    noColor: !!process.env.NO_COLOR,
    noRemediation: false,
    fix: false,
    dryRun: false,
    knownLanguagesOnly: false,
    ignore: [],
    noConfig: false,
    includeDesignSmells: false,
    showHelp: false,
    showVersion: false,
  };

  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') return { help: true };
    if (a === '-v' || a === '--version') return { version: true };
    if (a === '--format') {
      const v = argv[++i];
      if (v !== 'human' && v !== 'json' && v !== 'sarif' && v !== 'markdown') {
        return { error: `--format must be human|json|sarif|markdown (got ${v})` };
      }
      args.format = v;
      continue;
    }
    if (a === '--out') {
      args.outFile = argv[++i];
      continue;
    }
    if (a === '--mode') {
      const v = argv[++i];
      if (v !== 'fast' && v !== 'standard' && v !== 'deep') {
        return { error: `--mode must be fast|standard|deep (got ${v})` };
      }
      args.mode = v;
      continue;
    }
    if (a === '--fail-on') {
      const v = argv[++i];
      if (v !== 'critical' && v !== 'high' && v !== 'medium' && v !== 'low' && v !== 'never') {
        return { error: `--fail-on invalid (got ${v})` };
      }
      args.failOn = v;
      continue;
    }
    if (a === '--min-confidence') {
      const v = argv[++i];
      if (v !== 'high' && v !== 'medium' && v !== 'low') {
        return { error: `--min-confidence must be high|medium|low (got ${v})` };
      }
      args.minConfidence = v;
      continue;
    }
    if (a === '--ignore') {
      const v = argv[++i];
      if (!v) return { error: '--ignore requires a value' };
      args.ignore.push(v);
      continue;
    }
    if (a === '--diff') {
      const v = argv[++i];
      if (!v) return { error: '--diff requires a git range (e.g. main...HEAD)' };
      args.diff = v;
      continue;
    }
    if (a === '--known-only') {
      args.knownLanguagesOnly = true;
      continue;
    }
    if (a === '--config') {
      const v = argv[++i];
      if (!v) return { error: '--config requires a path' };
      args.config = v;
      continue;
    }
    if (a === '--no-config') {
      args.noConfig = true;
      continue;
    }
    if (a === '--include-design-smells') {
      args.includeDesignSmells = true;
      continue;
    }
    if (a === '--fix') {
      args.fix = true;
      continue;
    }
    if (a === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (a === '--no-remediation') {
      args.noRemediation = true;
      continue;
    }
    if (a === '--no-color' || a === '--no-colour') {
      args.noColor = true;
      continue;
    }
    if (a && a.startsWith('--')) {
      return { error: `unknown option: ${a}` };
    }
    if (a) positional.push(a);
  }

  if (positional.length === 0) {
    // With --diff, the path defaults to the current working directory
    // (the diff is the source of truth for which files to read).
    if (args.diff) {
      args.target = '.';
      return args;
    }
    return { help: true };
  }
  if (positional.length > 1) {
    return { error: `expected exactly one path, got ${positional.length}` };
  }
  args.target = positional[0]!;
  return args;
}

export const HELP_TEXT = HELP;

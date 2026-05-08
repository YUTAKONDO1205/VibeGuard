import type { ScanMode } from '@vibeguard/findings-schema';

export interface CliArgs {
  target: string;
  format: 'human' | 'json' | 'sarif' | 'markdown';
  outFile?: string;
  mode: ScanMode;
  failOn: 'critical' | 'high' | 'medium' | 'low' | 'never';
  noColor: boolean;
  noRemediation: boolean;
  knownLanguagesOnly: boolean;
  ignore: string[];
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
  --ignore <name>               Extra directory name to ignore (repeatable)
  --known-only                  Only scan files whose extension maps to a known language
  --no-remediation              Skip remediation generation
  --no-color                    Disable ANSI colours
  -h, --help                    Show this help
  -v, --version                 Print version

Examples:
  vibeguard ./src
  vibeguard ./src --format sarif --out report.sarif
  vibeguard suspicious.py --fail-on critical
`;

export function parseArgs(argv: string[]): CliArgs | { help: true } | { version: true } | { error: string } {
  const args: CliArgs = {
    target: '',
    format: 'human',
    mode: 'standard',
    failOn: 'high',
    noColor: !!process.env.NO_COLOR,
    noRemediation: false,
    knownLanguagesOnly: false,
    ignore: [],
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
    if (a === '--ignore') {
      const v = argv[++i];
      if (!v) return { error: '--ignore requires a value' };
      args.ignore.push(v);
      continue;
    }
    if (a === '--known-only') {
      args.knownLanguagesOnly = true;
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

  if (positional.length === 0) return { help: true };
  if (positional.length > 1) {
    return { error: `expected exactly one path, got ${positional.length}` };
  }
  args.target = positional[0]!;
  return args;
}

export const HELP_TEXT = HELP;

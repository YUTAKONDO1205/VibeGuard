// VG-EMB 18 FIX — turn deterministic auto-fixes into a pull request.
//
// This is a REPO-SIDE wrapper, deliberately kept out of the shipped CLI binary:
// the four distributed channels (CLI / Action / VS Code / Chrome) must stay
// zero-send and free of a GitHub dependency, so the `git`/`gh` coupling lives
// here in a script the maintainer runs, not in `@vibeguard/cli`.
//
// Flow (all local except the final push + gh call, which the user opts into):
//   1. dry-run the fixer to show what will change (nothing written yet),
//   2. require a clean working tree so the PR contains ONLY autofix edits,
//   3. apply the fixes with `vibeguard --fix`,
//   4. if the tree changed, branch + commit + push + `gh pr create`.
//
// Usage:
//   node scripts/fix-pr.mjs <target> [--yes] [--base <branch>] [-- <vibeguard args...>]
//
// Without --yes it stops after step 3 (fixes applied, no branch/push) so you can
// eyeball `git diff` first. With --yes it opens the PR.
import { spawnSync } from 'node:child_process';

const CLI = 'apps/cli/dist/index.js';

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { encoding: 'utf8', ...opts });
}

function fail(msg) {
  process.stderr.write(`fix-pr: ${msg}\n`);
  process.exit(1);
}

function parseArgv(argv) {
  const out = { target: '.', yes: false, base: 'main', passthrough: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--yes') out.yes = true;
    else if (a === '--base') out.base = argv[++i];
    else if (a === '--') {
      out.passthrough = argv.slice(i + 1);
      break;
    } else if (!a.startsWith('-')) out.target = a;
    else fail(`unknown option: ${a}`);
  }
  return out;
}

const opts = parseArgv(process.argv.slice(2));

// The CLI must be built — this wrapper runs the compiled binary, not the source.
if (run('node', [CLI, '--version']).status !== 0) {
  fail(`cannot run ${CLI} — build first: npm run build`);
}

// Step 1: preview.
process.stdout.write('── fix plan (dry run) ──\n');
const preview = run('node', [CLI, opts.target, '--dry-run', '--no-color', ...opts.passthrough]);
process.stdout.write(preview.stdout);
if (preview.status !== 0) fail('dry run failed');
if (/^No auto-fixable findings/m.test(preview.stdout)) {
  process.stdout.write('Nothing to fix.\n');
  process.exit(0);
}

// Step 2: a clean tree, so the PR diff is exactly the autofix and nothing else.
const dirty = run('git', ['status', '--porcelain']).stdout.trim();
if (dirty) fail('working tree is not clean — commit or stash first so the PR is only autofix edits');

// Step 3: apply.
process.stdout.write('\n── applying fixes ──\n');
const applied = run('node', [CLI, opts.target, '--fix', '--no-color', ...opts.passthrough]);
process.stdout.write(applied.stdout);
if (applied.status !== 0) fail('applying fixes failed');

const changed = run('git', ['diff', '--name-only']).stdout.trim();
if (!changed) {
  process.stdout.write('No files changed after apply.\n');
  process.exit(0);
}

if (!opts.yes) {
  process.stdout.write(
    '\nFixes applied to the working tree. Review `git diff`, then re-run with --yes to open a PR.\n',
  );
  process.exit(0);
}

// Step 4: branch + commit + push + PR. Branch name is derived from HEAD so a
// re-run on the same commit is stable (no Date/random in the name).
const head = run('git', ['rev-parse', '--short', 'HEAD']).stdout.trim();
const branch = `vibeguard/autofix-${head}`;
const files = changed.split('\n');

const body = [
  'Deterministic, LLM-free auto-fixes from `vibeguard --fix`.',
  '',
  'Each edit is provably correct from the file bytes alone; edits tagged',
  '`needs-review` change behaviour (fail-closed) and want a human eye.',
  '',
  '```',
  preview.stdout.trim(),
  '```',
  '',
  '🤖 Generated with [Claude Code](https://claude.com/claude-code)',
].join('\n');

const steps = [
  ['git', ['checkout', '-b', branch]],
  ['git', ['add', ...files]],
  ['git', ['commit', '-m', 'Apply vibeguard deterministic auto-fixes']],
  ['git', ['push', '-u', 'origin', branch]],
  ['gh', ['pr', 'create', '--base', opts.base, '--head', branch, '--title', 'vibeguard: deterministic auto-fixes', '--body', body]],
];
for (const [cmd, args] of steps) {
  process.stdout.write(`\n$ ${cmd} ${args.slice(0, 2).join(' ')} …\n`);
  const r = run(cmd, args, { stdio: 'inherit' });
  if (r.status !== 0) fail(`${cmd} ${args[0]} failed`);
}
process.stdout.write('\nPR opened.\n');

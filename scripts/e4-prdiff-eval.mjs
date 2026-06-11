// E4 — PR-diff scan evaluation (reproduces the paper's Table "PR差分スキャン").
//
// Builds a small git corpus (9 vulnerable files copied from samples/vulnerable
// plus one safe file), commits it as the baseline, then applies three PR
// scenarios and compares a repo-wide scan against `--diff` (added-lines-only):
//   A — a NEW file containing a vulnerable `eval(input)` line is added;
//   B — only SAFE lines are appended to an existing vulnerable file;
//   C — a vulnerable `os.system(...)` line is appended to a safe file.
// Reduction rate R = 1 - |F_diff| / |F_all|.
//
// Run from the repo root (after `npm run build`):
//   node scripts/e4-prdiff-eval.mjs
// Writes paper_data/e4_prdiff.json and prints a markdown table.
import { execSync } from 'node:child_process';
import { mkdirSync, rmSync, copyFileSync, writeFileSync, appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve('.');
const CLI = join(ROOT, 'apps', 'cli', 'dist', 'index.js');
const WORK = join(ROOT, 'paper_data', 'e4work');

const BASE_FILES = [
  'ai_artifacts.js', 'auth_bypass.py', 'command_injection.py', 'django_settings.py',
  'express_session.js', 'flask_app.py', 'secrets.js', 'sql_injection.py', 'xss.js',
];

const SAFE_APP = `import sqlite3
def get_user(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE id = ?", (uid,))
    return cur.fetchone()
`;

const NEW_API_JS = `function handler(input) {
  // process user input
  return eval(input);
}
`;

const B_SAFE_APPEND = `
def get_session(conn, sid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE id = ?", (sid,))
    return cur.fetchone()
`;

const C_VULN_APPEND = `
import os
def run(cmd):
    os.system("sh -c " + cmd)
`;

const sh = (cmd, cwd = WORK) => execSync(cmd, { cwd, stdio: 'pipe' }).toString();
const scan = (args) => {
  const out = execSync(`node "${CLI}" . --format json --fail-on never --no-config ${args}`, {
    cwd: WORK, stdio: 'pipe', maxBuffer: 64 * 1024 * 1024,
  }).toString();
  return JSON.parse(out).findings;
};

// --- baseline corpus --------------------------------------------------------
if (existsSync(WORK)) rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });
for (const f of BASE_FILES) copyFileSync(join(ROOT, 'samples', 'vulnerable', f), join(WORK, f));
writeFileSync(join(WORK, 'safe_app.py'), SAFE_APP);
sh('git init --quiet -b main');
sh('git -c user.email=e4@example.com -c user.name=e4 add -A');
sh('git -c user.email=e4@example.com -c user.name=e4 commit --quiet -m baseline');

const baseFull = scan('');
const rows = [];
const scenario = (key, label, apply) => {
  sh('git checkout --quiet -f main');
  sh(`git checkout --quiet -b ${key}`);
  apply();
  sh('git -c user.email=e4@example.com -c user.name=e4 add -A');
  sh(`git -c user.email=e4@example.com -c user.name=e4 commit --quiet -m ${key}`);
  const full = scan('');
  const diff = scan('--diff HEAD~1..HEAD');
  const R = full.length ? +(1 - diff.length / full.length).toFixed(3) : 0;
  rows.push({
    scenario: key, label, full: full.length, diff: diff.length, R,
    kept: diff.map((f) => `${f.ruleId} ${f.severity} L${f.startLine}`),
  });
};

scenario('A', '新規ファイルに脆弱コード追加', () => writeFileSync(join(WORK, 'new_api.js'), NEW_API_JS));
scenario('B', '既存脆弱ファイルに安全行のみ追加', () =>
  appendFileSync(join(WORK, 'sql_injection.py'), B_SAFE_APPEND));
scenario('C', '既存安全ファイルに脆弱行追加', () =>
  appendFileSync(join(WORK, 'safe_app.py'), C_VULN_APPEND));

const result = { baselineFull: baseFull.length, scenarios: rows };
writeFileSync(join(ROOT, 'paper_data', 'e4_prdiff.json'), JSON.stringify(result, null, 2) + '\n');

console.log(`# E4 — PR-diff scan (baseline full scan: ${baseFull.length} findings)\n`);
console.log('| scenario | full scan | diff scan | R | kept findings |');
console.log('|---|---|---|---|---|');
for (const r of rows) {
  console.log(`| ${r.scenario} ${r.label} | ${r.full} | ${r.diff} | ${(r.R * 100).toFixed(1)}% | ${r.kept.join('; ') || '—'} |`);
}
rmSync(WORK, { recursive: true, force: true });

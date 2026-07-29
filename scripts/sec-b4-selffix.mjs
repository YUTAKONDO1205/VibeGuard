#!/usr/bin/env node
// sec-b4-selffix — B4: does the tool's OWN remediation / veto machinery satisfy
// the B1 win condition (finding gone ∧ defect alive)?
//
// The B-series measures an ADVERSARY transforming code until the detector goes
// quiet. B4 keeps the win condition and changes the actor: the transformation is
// applied by VibeGuard itself (`--fix`), or invited by the rule's own published
// remediation. Nothing here is a new metric — each case is scored with the B1
// predicate so the numbers drop straight into the existing evasion table with one
// extra column, `origin ∈ {adversarial, defender}`.
//
// Five cases, each an independent chokepoint:
//   A1  detection granularity ≠ fix granularity   (VG-INJ-020)
//   A2  reported position ≠ edited position       (VG-EMB-010)
//   A3  aggregation veto fails OPEN               (VG-SMELL-012 — DECLARED)
//   E   value semantics ≠ definedness semantics   (VG-EMB-020 / 021)
//   G   fix mode neutralises the --fail-on gate   (CLI wiring; the amplifier)
//
// Run:  node scripts/sec-b4-selffix.mjs [--out <path>]
// Out:  security-experiment/_results/sec-b4-selffix.json
//
// Deterministic: fixtures are written by this script, no timestamps in the
// output, no network. Requires a current build (`npm run build`).
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const FIXTURES = join(ROOT, 'security-experiment', 'track-a-tool-security', 'b4-selffix');
const CLI = join(ROOT, 'apps', 'cli', 'dist', 'index.js');

const outArg = process.argv.indexOf('--out');
const OUT =
  outArg !== -1 && process.argv[outArg + 1]
    ? resolve(process.argv[outArg + 1])
    : join(ROOT, 'security-experiment', '_results', 'sec-b4-selffix.json');

const rules = await import(pathToFileURL(join(ROOT, 'packages/rules/dist/index.js')).href);
const remediation = await import(
  pathToFileURL(join(ROOT, 'packages/remediation-engine/dist/index.js')).href
);
const core = await import(pathToFileURL(join(ROOT, 'packages/analyzer-core/dist/index.js')).href);

const ctxFor = (content, language, filePath = 'fixture') => ({
  filePath,
  content,
  lines: content.split('\n'),
  language,
});

/** Write a fixture and return its absolute path. */
function fixture(rel, content) {
  const p = join(FIXTURES, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content, 'utf8');
  return p;
}

/** Scan a path with the shipped CLI and return {exitCode, findings}. */
function cliScan(target, extraArgs = []) {
  const r = spawnSync(process.execPath, [CLI, target, '--format', 'json', ...extraArgs], {
    encoding: 'utf8',
  });
  let parsed = null;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    /* fix mode and error paths do not emit JSON */
  }
  return { exitCode: r.status, findings: parsed?.findings ?? null, stdout: r.stdout };
}

/** Exit code only — for the gate cases, where stdout is a fix report. */
function cliExit(target, extraArgs) {
  return spawnSync(process.execPath, [CLI, target, ...extraArgs], { encoding: 'utf8' }).status;
}

const cases = [];

// ── A1 — detection granularity ≠ fix granularity (VG-INJ-020) ────────────────
//
// `FOR_IN` (injection.ts) is NOT global, so the rule reports the FIRST for-in in
// the function while the write/recursion conjuncts are tested against the WHOLE
// body. When the first loop is harmless and a later one carries the recursion,
// the finding points at the harmless loop and the fixer, anchored to that
// column, edits there — leaving the dangerous loop untouched while the report
// says a fix was applied.
{
  const src = [
    'function merge(dst, src) {',
    '  for (const a in src.meta) {',
    '    dst.meta[a] = src.meta[a];',
    '  }',
    '  for (const k in src) {',
    '    if (typeof src[k] === "object" && src[k] !== null) merge(dst[k], src[k]);',
    '    else dst[k] = src[k];',
    '  }',
    '  return dst;',
    '}',
    '',
  ].join('\n');

  const rule = rules.getRule('VG-INJ-020');
  const before = rule.match(ctxFor(src, 'javascript'));

  // PoC oracle: does a __proto__ key reach Object.prototype?
  const pollutes = (code) => {
    const fn = new Function(`${code}; return merge;`)();
    delete Object.prototype.b4Polluted;
    try {
      fn({}, JSON.parse('{"__proto__":{"b4Polluted":"YES"}}'));
    } catch {
      /* a throw is not pollution */
    }
    const hit = {}.b4Polluted === 'YES';
    delete Object.prototype.b4Polluted;
    return hit;
  };

  const fix = before.length ? remediation.buildFix('VG-INJ-020', src, before[0]) : null;
  const fixed = fix ? remediation.applyFixes(src, fix.edits) : src;
  const after = rule.match(ctxFor(fixed, 'javascript'));

  fixture('a1/merge.js', src);
  if (fix) fixture('a1/merge.fixed.js', fixed);

  cases.push({
    id: 'A1',
    ruleId: 'VG-INJ-020',
    chokepoint: 'detection granularity != fix granularity',
    origin: 'defender',
    reportedAt: before.map((m) => `L${m.startLine}C${m.startColumn}`),
    reportedEvidence: before.map((m) => m.evidence),
    fixOffered: Boolean(fix),
    fixTitle: fix?.title ?? null,
    fixSafety: fix?.safety ?? null,
    findingsBefore: before.length,
    findingsAfter: after.length,
    defectAliveBefore: pollutes(src),
    defectAliveAfter: pollutes(fixed),
    // B1 predicate, defender-origin: the tool's own edit silenced the detector
    // while the defect survived.
    b1WinCondition: before.length > 0 && after.length === 0 && pollutes(fixed),
  });
}

// ── A2 — reported position ≠ edited position (VG-EMB-010) ────────────────────
//
// The finding comes from the canonical (fold) face, so its column is valid on the
// original bytes but does not contain the payload. `tokenSwap` searches FORWARD
// from that column, and the fixer's pattern lacks the loopback negative lookahead
// the rule's own pattern carries — so the edit lands on a token the detector
// deliberately excluded.
{
  const src = [
    'void f(void) {',
    '  http_get("htt" "p://evil.example/x"); local_get("http://localhost/health");',
    '}',
    '',
  ].join('\n');
  const p = fixture('a2/endpoint.c', src);

  const before = cliScan(dirname(p));
  const fixRun = spawnSync(process.execPath, [CLI, dirname(p), '--fix', '--no-color'], {
    encoding: 'utf8',
  });
  const { readFileSync } = await import('node:fs');
  const afterBytes = readFileSync(p, 'utf8');
  const after = cliScan(dirname(p));
  const secondFix = spawnSync(process.execPath, [CLI, dirname(p), '--fix', '--no-color'], {
    encoding: 'utf8',
  });

  cases.push({
    id: 'A2',
    ruleId: 'VG-EMB-010',
    chokepoint: 'reported position != edited position',
    origin: 'defender',
    findingsBefore: (before.findings ?? []).length,
    findingsAfter: (after.findings ?? []).length,
    claimedApplied: /Applied \d+ fix/.test(fixRun.stdout),
    // The payload the detector reported must survive untouched for this to be a
    // mis-target rather than a fix.
    reportedPayloadStillPresent: afterBytes.includes('"htt" "p://evil.example/x"'),
    // The loopback URL is excluded by the rule's own lookahead; if it changed,
    // the fixer edited something the detector declared out of scope.
    excludedTokenEdited: afterBytes.includes('https://localhost/health'),
    reachesFixpoint: /^No auto-fixable findings/m.test(secondFix.stdout),
    // Not a silencing case: the win condition here is "the fix introduces a new
    // defect while the reported one survives".
    b1WinCondition: false,
    fixIntroducesDefect:
      afterBytes.includes('https://localhost/health') &&
      afterBytes.includes('"htt" "p://evil.example/x"'),
  });

  // Restore the fixture so a re-run measures the same starting bytes.
  writeFileSync(p, src, 'utf8');
}

// ── A3 — aggregation veto fails OPEN (VG-SMELL-012) ──────────────────────────
//
// `ROLE_MITIGATION` vetoes the WHOLE FILE. Applying the rule's own published
// remediation at ONE site therefore deletes the findings for every remaining
// site. No --fix is involved: the rule invites the edit.
{
  const site = "  return user.role === 'admin';";
  const bare = [
    'function canEdit(user) {',
    site,
    '}',
    '',
    'function canDelete(user) {',
    site,
    '}',
    '',
    'function canPublish(user) {',
    site,
    '}',
    '',
    'function canInvite(user) {',
    site,
    '}',
    '',
    'module.exports = { canEdit, canDelete, canPublish, canInvite };',
    '',
  ].join('\n');
  // Exactly the migration the rule's remediation prescribes, applied to 1 of 4.
  const partial = ["const Role = Object.freeze({ ADMIN: 'admin' });", ''].join('\n') +
    bare.replace(site, '  return user.role === Role.ADMIN;');

  const bareDir = dirname(fixture('a3-bare/roles.js', bare));
  const partialDir = dirname(fixture('a3-partial/roles.js', partial));

  const b = cliScan(bareDir);
  const a = cliScan(partialDir);
  const remaining = (partial.match(/=== 'admin'/g) ?? []).length;

  cases.push({
    id: 'A3',
    ruleId: 'VG-SMELL-012',
    chokepoint: 'file-global mitigation veto fails open',
    origin: 'defender',
    // DECLARED, not a defect — and publishable for that reason: every fact this
    // case rests on is already derivable from the published tree, so nothing new
    // is disclosed by measuring it. `design-smells-single.ts` states the policy
    // in prose ("suppress the whole file. Conservative by design (a false
    // negative here, never a false positive)") and `audit-regressions.test.ts`
    // pins it with a regression test built from this very shape — including
    // three sibling tests proving a MENTION of the mitigation (in a string or a
    // comment) does NOT veto. The authors considered veto forgery and closed it;
    // what remains is the deliberate recall cost of the real signal.
    //
    // It stays in this harness because the paper's claim is not "there is a bug"
    // but "the FP-suppression benefit and the concealment surface are the same
    // mechanism". A declared instance is the strongest possible form of that
    // claim: the trade is documented, tested, and still buys an attacker (or an
    // honest partial migration) the disappearance of three high findings.
    channel: 'declared',
    declaredAt: [
      'packages/rules/src/rules/design-smells-single.ts:333-335',
      'packages/rules/src/rules/audit-regressions.test.ts:107-110',
    ],
    sitesTotal: 4,
    sitesMigrated: 1,
    findingsBefore: (b.findings ?? []).length,
    findingsAfter: (a.findings ?? []).length,
    unmigratedSitesRemaining: remaining,
    gateExitBefore: cliExit(bareDir, ['--fail-on', 'high']),
    gateExitAfter: cliExit(partialDir, ['--fail-on', 'high']),
    // Defect alive = raw role comparisons still in the file.
    defectAliveAfter: remaining > 0,
    b1WinCondition: (b.findings ?? []).length > 0 && (a.findings ?? []).length === 0 && remaining > 0,
  });
}

// ── G — fix mode neutralises the --fail-on gate (the amplifier) ──────────────
//
// VG-INJ-005 has NO fixer, so nothing can be fixed; the only variable is whether
// fix mode reports the gate.
{
  const src = 'import pickle\ndef load(blob):\n    return pickle.loads(blob)\n';
  const dir = dirname(fixture('gate/evil.py', src));
  cases.push({
    id: 'G',
    ruleId: 'VG-INJ-005',
    chokepoint: 'fix mode returns 0 regardless of --fail-on',
    origin: 'defender',
    hasFixer: false,
    exitScanOnly: cliExit(dir, ['--fail-on', 'high']),
    exitWithFix: cliExit(dir, ['--fail-on', 'high', '--fix']),
    exitWithDryRun: cliExit(dir, ['--fail-on', 'high', '--dry-run']),
    gateHolds:
      cliExit(dir, ['--fail-on', 'high', '--fix']) === 1 &&
      cliExit(dir, ['--fail-on', 'high', '--dry-run']) === 1,
  });
}

// ── E — value semantics vs definedness semantics (VG-EMB-020 / VG-EMB-021) ───
//
// `#define FLAG 1` → `0` disables the flag only where the code reads its VALUE
// (`#if FLAG`). Where it asks whether the macro is DEFINED (`#ifdef FLAG`,
// `#if defined(FLAG)`) a zero is still a definition and the guarded code still
// compiles, so the swap was an incomplete fix. VG-EMB-020 additionally PUBLISHED
// the swap as its `exampleFix`, so following the rule's own written advice
// produced the same incomplete outcome with no fixer involved. Both fixers now
// decline; the `exampleFix` is gone.
//
// SCOPE: this case measures the REMEDIATION side only. What the rules do or do
// not detect around the same distinction is a separate question, tracked outside
// the published tree until its own answer ships.
{
  const src = [
    '#define BYPASS_AUTH 1',
    '#define DEBUG 1',
    '',
    'int check(void) {',
    '#ifdef BYPASS_AUTH',
    '  return AUTH_OK;',
    '#endif',
    '  return verify();',
    '}',
    '',
    'void log_it(void) {',
    '#if defined(DEBUG)',
    '  serial_print(admin_password);',
    '#endif',
    '}',
    '',
  ].join('\n');
  const dir = dirname(fixture('e-ifdef/fw.c', src));

  const before = cliScan(dir);
  spawnSync(process.execPath, [CLI, dir, '--fix', '--no-color'], { encoding: 'utf8' });
  const { readFileSync: rf } = await import('node:fs');
  const afterBytes = rf(join(dir, 'fw.c'), 'utf8');
  const after = cliScan(dir);

  cases.push({
    id: 'E',
    ruleId: 'VG-EMB-020 / VG-EMB-021',
    chokepoint: 'value semantics assumed where the code uses definedness semantics',
    origin: 'defender',
    channel: 'undeclared',
    findingsBefore: (before.findings ?? []).length,
    findingsAfter: (after.findings ?? []).length,
    // The defect is alive whenever the definedness branches are still compiled,
    // i.e. whenever the #define survives in any form.
    defectAliveAfter: /#[ \t]*define[ \t]+BYPASS_AUTH\b/.test(afterBytes),
    fileChanged: afterBytes !== src,
    b1WinCondition:
      (before.findings ?? []).length > 0 &&
      (after.findings ?? []).length === 0 &&
      /#[ \t]*define[ \t]+BYPASS_AUTH\b/.test(afterBytes),
  });

  writeFileSync(join(dir, 'fw.c'), src, 'utf8');
}

// NOTE — one case of this study is deliberately ABSENT from this file.
//
// A sixth case (a guard-vocabulary veto that an unreferenced string literal can
// forge) is measured by a harness kept OUTSIDE the published tree, under
// `security-experiment/` (git-ignored), because it is UNFIXED. `SCOPE.md` §8
// permits publishing concealment and evasion techniques only together with their
// mitigation, and forbids a bypass recipe on its own; the same rule the project
// applied when it stripped copy-pasteable payloads out of a CHANGELOG entry that
// would otherwise have advertised an unpatched release. Every case that IS here
// ships with the change that closes it, or (A3) with the rule's own written
// statement that the trade is intentional. The absent case moves into this file
// when its mitigation does.

const report = {
  experiment: 'sec-b4-selffix',
  engineVersion: core.ENGINE_VERSION,
  note:
    'B1 win condition (finding gone AND defect alive) scored with origin=defender: ' +
    'the transformation is applied by the tool itself or invited by its own remediation.',
  cases,
  summary: {
    // Only UNDECLARED wins are defects. A declared channel is a documented,
    // regression-tested trade — it is reported, never silently "fixed".
    b1WinsUndeclared: cases.filter((c) => c.b1WinCondition && c.channel !== 'declared').length,
    b1WinsDeclared: cases.filter((c) => c.b1WinCondition && c.channel === 'declared').length,
    b1Wins: cases.filter((c) => c.b1WinCondition).length,
    fixIntroducesDefect: cases.filter((c) => c.fixIntroducesDefect).length,
    gateHolds: cases.find((c) => c.id === 'G')?.gateHolds ?? null,
  },
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

for (const c of cases) {
  const verdict = c.b1WinCondition
    ? c.channel === 'declared'
      ? 'B1-WIN (DECLARED channel — reported, not fixed)'
      : 'B1-WIN (finding gone, defect alive)'
    : c.fixIntroducesDefect
      ? 'FIX-INTRODUCES-DEFECT'
      : c.id === 'G'
        ? c.gateHolds
          ? 'gate holds'
          : 'GATE NEUTRALISED'
        : 'no win';
  console.log(`${c.id.padEnd(3)} ${String(c.ruleId).padEnd(14)} ${verdict}`);
}
console.log(`\nengine ${report.engineVersion} -> ${OUT}`);
rmSync(join(FIXTURES, 'a1', 'merge.fixed.js'), { force: true });

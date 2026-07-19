// vibeguard:disable-file VG-AUTH-001 VG-INJ-007
// The fixtures below are deliberately vulnerable snippets — `if (DEBUG) { return
// true; }`, `os.path.join(root, user_input)` — because their whole purpose is to
// be matched by the rules under test. VibeGuard flags them correctly; the
// self-scan gate would otherwise fail on its own test data. Same treatment as
// packages/rules/src/rules/*.ts, which disable the rules they define fixtures for.
//
// A1 — joint check: does a rewrite keep REAL multi-line code shapes matching,
// AND stay linear?
//
// WHY THIS EXISTS. The first L1 rewrite pass replaced every `\s` with the
// horizontal-only class `[^\S\r\n]`, which fixed the ReDoS but silently broke
// detection on code that legitimately spans lines:
//
//   catch (Exception e)      <- Allman brace, the dominant Java/C# style
//   {
//   }
//   os.path.join(            <- black-formatted Python, the standard formatter
//       root,
//       user_input
//   )
//
// Six such shapes matched before the rewrite and missed after. The regression
// corpus (samples/ + test_problem/) contained none of them, so the "zero-diff"
// differential passed and gave false confidence. A rewrite has TWO obligations
// and the differential only checked one.
//
// THE FIX SHAPE. `\s` must not be banned, only BOUNDED. `\s` crossing an
// unbounded run of blank lines is what backtracks; `\s{0,K}` for a small K
// spans the one or two line breaks real code uses and cannot blow up, because a
// bounded quantifier has a bounded number of split points. This script measures
// both properties for a candidate so neither can be traded away silently.
//
// Run:  node scripts/sec-a1-shape-check.mjs
import { performance } from 'node:perf_hooks';

// Each entry: the shipped pattern, a candidate, the shapes that MUST match, and
// the shapes that must NOT. Literals only — never build a regex from an escaped
// string (the shell and JS string literal each eat backslashes; a mangled
// pattern stops backtracking, measures fast, and yields a false pass).
const CASES = [
  {
    id: 'VG-QUAL-001#1 catch',
    shipped: /catch[^\S\r\n]*\([^()\r\n]*\)[^\S\r\n]*\{\s*\}/g,
    candidate: /catch\s{0,20}\([^()\r\n]{0,200}\)\s{0,20}\{\s{0,20}\}/g,
    must: ['catch (Exception e) {\n}', 'catch (Exception e)\n{\n}', 'catch (e)\n    {\n    }'],
    mustNot: ['catch (e) { log(e); }', 'catchword (e) {}'],
  },
  {
    id: 'VG-INJ-007 path-join',
    shipped: /(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|open)|open|os\.path\.join)[^\S\r\n]*\([^()\n]*[+,][^\S\r\n]*\w+/g,
    candidate: /(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|open)|open|os\.path\.join)\s{0,20}\([^()]{0,200}[+,]\s{0,20}\w+/g,
    must: ['os.path.join(root, user_input)', 'os.path.join(\n    root,\n    user_input\n)', 'fs.readFile(dir + name)'],
    mustNot: ['os.path.join()', 'joinother(a, b)'],
  },
  {
    id: 'VG-INJ-003 os.system',
    shipped: /os\.(?:system|popen)[^\S\r\n]*\((?:[^\S\r\n]*f["']|[^\S\r\n]*["'][^"'\n]*["'][^\S\r\n]*[+%]|.*\{)/g,
    candidate: /os\.(?:system|popen)\s{0,20}\((?:\s{0,20}f["']|\s{0,20}["'][^"'\n]{0,200}["']\s{0,20}[+%]|[^\n]{0,200}\{)/g,
    must: ['os.system(f"ls {d}")', 'os.system(\n    f"ls {d}"\n)', 'os.system("ls " + d)'],
    mustNot: ['os.system()', 'os.getcwd()'],
  },
  {
    id: 'VG-QUAL-005#3 stub-return',
    shipped: /^[^\S\r\n]*return[^\S\r\n]+(?:null|None|nil|undefined|true|false)[^\S\r\n]*(?:;[^\S\r\n]*)?(?:\r?\n[^\S\r\n]*)?(?:#|\/\/)[^\S\r\n]*(?:TODO|FIXME|stub|implement\b)/gim,
    candidate: /^[^\S\r\n]*return[^\S\r\n]+(?:null|None|nil|undefined|true|false)[^\S\r\n]*(?:;[^\S\r\n]*)?\s{0,40}(?:#|\/\/)[^\S\r\n]*(?:TODO|FIXME|stub|implement\b)/gim,
    must: ['return null // TODO', 'return True\n    # TODO', 'return True\n\n# TODO implement'],
    mustNot: ['return userValue // ok', 'returnValue = 1'],
  },
  {
    id: 'VG-QUAL-010#2 python-def',
    shipped: /^[^\S\r\n]*def[^\S\r\n]+(?:validate|sanitize|sanitise|check|verify)\w*[^\S\r\n]*\([^)\n]*\)[^\S\r\n]*:[^\S\r\n]*(?:\n[^\S\r\n]*(?:'''|""")[^\n]*(?:'''|""")[^\S\r\n]*)?\n[^\S\r\n]*return[^\S\r\n]+(?:True|input|value|val|x|data|args?\[0\])[^\S\r\n]*$/gim,
    candidate: /^[^\S\r\n]*def[^\S\r\n]+(?:validate|sanitize|sanitise|check|verify)\w*\s{0,20}\([^()]{0,200}\)\s{0,20}:[^\S\r\n]*(?:\n[^\S\r\n]*(?:'''|""")[^\n]{0,200}(?:'''|""")[^\S\r\n]*)?\s{0,40}return[^\S\r\n]+(?:True|input|value|val|x|data|args?\[0\])[^\S\r\n]*$/gim,
    must: [
      'def validate(x):\n    return True',
      'def validate(\n    x,\n):\n    return True',
      'def check(a):\n    """doc"""\n    return input',
    ],
    mustNot: ['def validate(x):\n    return sanitize(x)', 'def other(x):\n    return True'],
  },
  {
    id: 'VG-AUTH-001 debug-bypass',
    shipped: /if[^\S\r\n]*(?:\([^\S\r\n]*)?(?:DEBUG|isDev|IS_DEV|process\.env\.NODE_ENV[^\S\r\n]*===?[^\S\r\n]*["']development["']|debug)[^\S\r\n]*(?:\)[^\S\r\n]*)?[:{][^}]{0,200}?(?:return[^\S\r\n]+true|skip[_\s]?auth|bypass|allow|permit)/gi,
    candidate: /if\s{0,20}(?:\(\s{0,20})?(?:DEBUG|isDev|IS_DEV|process\.env\.NODE_ENV\s{0,20}===?\s{0,20}["']development["']|debug)\s{0,20}(?:\)\s{0,20})?[:{][^}]{0,300}?(?:return\s{0,20}true|skip[_\s]?auth|bypass|allow|permit)/gi,
    must: [
      'if (DEBUG) { return true; }',
      'if (debug)\n{\n  return true;\n}',
      'if DEBUG:\n    return True  # skip auth',
      'if (\n  DEBUG\n) {\n  return true;\n}',
    ],
    mustNot: ['if (user.isAdmin) { return user; }', 'const debugLabel = "value";'],
  },
];

function timeExec(re, input, ceilingMs = 2000) {
  const r = new RegExp(re.source, re.flags);
  r.lastIndex = 0;
  const t0 = performance.now();
  let n = 0;
  while (r.exec(input) !== null) {
    n += 1;
    if (n > 50_000) break;
    if (performance.now() - t0 > ceilingMs) break;
  }
  return performance.now() - t0;
}

// The adversarial battery that broke the ORIGINAL patterns: unbounded runs of
// blank lines and of horizontal whitespace, plus near-misses that repeatedly
// enter and fail the pattern.
function battery(k) {
  return [
    '\n'.repeat(k),
    `${'\n'.repeat(k / 2)}\treturn nil\n${'\n'.repeat(k / 2)}`,
    `catch${' '.repeat(k)}(`,
    `os.path.join(${' '.repeat(k)}`,
    `if${' '.repeat(k)}(DEBUG`,
    `${'    \n'.repeat(k / 5)}`,
    `${'catch (e)\n'.repeat(k / 10)}`,
    `${'if (debug)\n'.repeat(k / 11)}`,
  ];
}

const LADDER = [2000, 8000, 32000, 128000];
const BUDGET_MS = 500;

let failures = 0;
for (const c of CASES) {
  const shapeMiss = c.must.filter((s) => {
    const r = new RegExp(c.candidate.source, c.candidate.flags);
    return !r.test(s);
  });
  const overBroad = c.mustNot.filter((s) => {
    const r = new RegExp(c.candidate.source, c.candidate.flags);
    return r.test(s);
  });
  // Shapes the SHIPPED pattern currently misses — i.e. what this candidate recovers.
  const shippedMiss = c.must.filter((s) => {
    const r = new RegExp(c.shipped.source, c.shipped.flags);
    return !r.test(s);
  });

  let worst = 0;
  for (const k of LADDER) {
    for (const input of battery(k)) worst = Math.max(worst, timeExec(c.candidate, input));
    if (worst > BUDGET_MS) break;
  }

  const ok = shapeMiss.length === 0 && overBroad.length === 0 && worst < BUDGET_MS;
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.id}`);
  console.log(`      recovers ${shippedMiss.length}/${c.must.length} shapes the shipped pattern misses`);
  console.log(`      worst ${worst.toFixed(1)}ms across the adversarial battery (budget ${BUDGET_MS}ms)`);
  if (shapeMiss.length) console.log(`      ⚠ candidate still MISSES: ${JSON.stringify(shapeMiss)}`);
  if (overBroad.length) console.log(`      ⚠ candidate OVER-MATCHES: ${JSON.stringify(overBroad)}`);
}
console.log(failures === 0 ? '\nAll candidates satisfy BOTH obligations.' : `\n${failures} candidate(s) failed.`);
process.exit(failures === 0 ? 0 : 1);

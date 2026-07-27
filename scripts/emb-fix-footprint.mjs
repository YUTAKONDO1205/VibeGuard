#!/usr/bin/env node
// vibeguard:disable-file VG-INJ-007 VG-CRYPTO-003 reason="C specimens are data, not code this repo runs"
// The C specimens below exist to TRIP the rules they are named after, and they
// live inside JS string literals, so the self-scan reads them as this file's own
// source: `open(path, O_WRONLY | …)` looks like a concatenated path (VG-INJ-007)
// and the plaintext telemetry URL looks like our endpoint (VG-CRYPTO-003).
// Same reason packages/rules/src/rules/embedded-ai.ts disables the rules it
// defines. Scoped to those two IDs, never a wildcard, so anything else this
// script grows still gets flagged.
//
// VG-EMB 18b FIX-EMB — measure the firmware footprint of the fixes VibeGuard
// actually emits.
//
// WHAT CHANGED FROM v1, AND WHY. v1 measured two hand-written before/after pairs
// (strcpy→snprintf, gets→fgets). Both are real fix shapes — but VibeGuard ships
// NO fixer for either rule, because the safe replacement needs a buffer size the
// source does not contain and inventing one is precisely what fixers.ts forbids.
// So the numbers described a patch a human might type, while the sentence they
// would be cited for is "this is what OUR patch costs". That gap is the kind of
// thing a reviewer finds, not the kind you get to explain afterwards.
//
// This version drives the real pipeline for the five rules that do have fixers:
//
//     specimen C → rule.match() → buildFix() → applyFixes() → after
//
// so the `after` side is the fixer's own output, byte for byte. Nothing about
// the fix is retyped here. The hand-written pairs are kept (they illustrate the
// cost the fixer table deliberately refuses to pay) but they are labelled
// 'hand-written' and rendered in a SEPARATE table — see renderMarkdownTable.
//
// WHAT IS MEASURED: one translation unit, `arm-none-eabi-gcc -mcpu=cortex-m4 -Os
// -Wall -c`, sized with `arm-none-eabi-size`. No link, no board core; every
// specimen is self-contained against newlib. `-Wall` changes no code generation —
// it is there so an implicit declaration (which would silently make us measure a
// different call) lands in the report instead of hiding.
//
// WHAT IS NOT MEASURED, and stays null rather than being faked:
//   - Arduino-API fixes (WiFi / Serial / HTTPClient): they need a board core to
//     compile. Stubbing the core would mean sizing OUR stub, not the fix.
//   - Whole-image cost. A delta on one .o is not a delta on a linked image: the
//     linker pulls printf's machinery in once, wherever it is first referenced.
//     What this table answers is the MARGINAL cost of the edit; it is not a
//     firmware size budget.
//   - Anything at all when the toolchain is absent — every row is null with
//     reason 'toolchain-absent', and a null is never rendered as 0.
//
// "+0 B" IS A RESULT, NOT A MISSING MEASUREMENT. A fix can genuinely cost
// nothing: VG-EMB-011 swaps one integer constant for another, and if both encode
// to the same instruction the honest answer is a measured zero. So a measured 0
// renders "+0 B" and a null renders "not measured (<reason>)", and the two are
// never interchangeable in either direction. Note also what a small number here
// does NOT mean: the real cost of that particular fix — a CA certificate in
// flash — is outside this translation unit, because the fixer does not install a
// CA (it cannot know which one). The note on that row says so.
//
// USAGE
//   node scripts/emb-fix-footprint.mjs [--markdown] [--json <path>] [--print-specimens]
//   node scripts/emb-fix-footprint.mjs --via-wsl [<distro>]   (from Windows)
//
// The toolchain lives in WSL2 on the dev box, the build lives on Windows. This
// script therefore imports the built `dist/` by RELATIVE PATH and uses nothing
// but node builtins: it must never make you run npm inside WSL, because this
// repo's node_modules sits on /mnt/c and an npm run from the Linux side rewrites
// bin shims and symlinks that the Windows install then trips over. Build on
// Windows (`npm run build`), measure from WSL (`node scripts/…`).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir, release as osRelease } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const GCC = 'arm-none-eabi-gcc';
const SIZE = 'arm-none-eabi-size';
// Exactly the documented compile line. -Os because that is what a firmware build
// uses, cortex-m4 because that is the class of part these rules target (M-profile
// implies Thumb, so -mthumb is redundant). Nothing here is tuning: a flag that
// changed code generation between runs would make the numbers unreproducible.
const BASE_CFLAGS = ['-mcpu=cortex-m4', '-Os', '-Wall', '-c'];

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
/** Value after `flag`, or null when it is absent or followed by another option. */
const optValue = (flag) => {
  const i = argv.indexOf(flag);
  if (i === -1) return null;
  const next = argv[i + 1];
  return next === undefined || next.startsWith('-') ? null : next;
};

if (has('--help') || has('-h')) {
  process.stdout.write(
    [
      'VG-EMB 18b — embedded fix footprint',
      '',
      '  node scripts/emb-fix-footprint.mjs [options]',
      '',
      '  --markdown           emit a markdown report on stdout (paste target: docs/)',
      '  --json <path>        also write the rows + toolchain metadata as JSON',
      '  --print-specimens    dump every before/after source and exit (no compiling)',
      '  --via-wsl [<distro>] re-run this script inside WSL, where the toolchain lives',
      '                       (default distro: Ubuntu-24.04)',
      '',
      'Build first, on Windows: npm run build. This script reads packages/*/dist.',
      'Redirect stdout to capture a report; --json paths must be visible to whichever',
      'side actually runs (with --via-wsl that is the Linux side).',
      '',
    ].join('\n'),
  );
  process.exit(0);
}

// ── running from Windows: hand the job to WSL ────────────────────────────────
// Kept as an opt-in flag rather than an automatic hop: an automatic one would
// silently measure on a machine you did not choose, and the whole point of this
// script is that you can say which instrument produced a number.
function toWslPath(winPath) {
  // Bounded quantifier, like every regex in this repo (D3): this one only ever
  // sees our own path, but "bounded unless proven otherwise" is the house rule
  // and an unbounded `.*` here would be the exception someone copies later.
  const m = /^([A-Za-z]):[\\/](.{0,4096})$/.exec(winPath);
  if (!m) return winPath.replace(/\\/g, '/');
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
}

if (has('--via-wsl')) {
  if (process.platform !== 'win32') {
    process.stderr.write('--via-wsl only makes sense from Windows; you are already on Linux.\n');
    process.exit(2);
  }
  const distroArg = optValue('--via-wsl');
  const distro = distroArg ?? 'Ubuntu-24.04';
  // Drop only the flag and, if one was given, the distro name — never a
  // following option (`--via-wsl --markdown` must still pass --markdown along).
  const passthrough = argv.filter((a, i) => {
    if (a === '--via-wsl') return false;
    return !(distroArg !== null && i === argv.indexOf('--via-wsl') + 1);
  });
  const scriptWsl = toWslPath(fileURLToPath(import.meta.url));

  // Probe before re-execing, so a missing node produces OUR message instead of a
  // bare 127 from the shell.
  const probe = spawnSync('wsl.exe', ['-d', distro, '--', 'node', '--version'], { encoding: 'utf8' });
  if (probe.error?.code === 'ENOENT') {
    process.stderr.write('wsl.exe not found — is WSL installed on this machine?\n');
    process.exit(2);
  }
  if (probe.status !== 0) {
    const detail = `${probe.stdout ?? ''}${probe.stderr ?? ''}`.trim();
    process.stderr.write(
      [
        `node is not runnable inside WSL distro "${distro}".`,
        detail ? `  (${detail.split('\n')[0]})` : '',
        '',
        'Install a Node runtime there, e.g.:  sudo apt install -y nodejs',
        '',
        'Do NOT run npm install / npm run build inside WSL. This repo lives on',
        '/mnt/c and npm rewrites bin shims and symlinks in a way the Windows-side',
        'install then trips over. Build on Windows; WSL needs only `node` and the',
        'arm-none-eabi toolchain.',
        '',
      ]
        .filter(Boolean)
        .join('\n'),
    );
    process.exit(2);
  }
  const run = spawnSync('wsl.exe', ['-d', distro, '--', 'node', scriptWsl, ...passthrough], {
    stdio: 'inherit',
  });
  process.exit(run.status ?? 1);
}

// ── the built engine (relative dist import; no package resolution, no npm) ────
const distUrl = (p) => new URL(`../packages/${p}`, import.meta.url).href;
let rulesMod;
let fixersMod;
let footprintMod;
try {
  [rulesMod, fixersMod, footprintMod] = await Promise.all([
    import(distUrl('rules/dist/index.js')),
    import(distUrl('remediation-engine/dist/fixers.js')),
    import(distUrl('remediation-engine/dist/footprint.js')),
  ]);
} catch (err) {
  process.stderr.write(
    [
      'cannot load packages/*/dist — this script measures the BUILT engine.',
      '',
      'Build on the Windows side first:  npm run build',
      'then re-run. (Never `npm run build` from WSL: node_modules on /mnt/c is a',
      'Windows install and npm will rewrite its shims.)',
      '',
      `  ${err instanceof Error ? err.message : String(err)}`,
      '',
    ].join('\n'),
  );
  process.exit(2);
}

const { getRule } = rulesMod;
const { buildFix, applyFixes, fixers } = fixersMod;
const { probeArmToolchain, parseSizeOutput, measureAll, renderFootprint, renderMarkdownTable, formatDelta } =
  footprintMod;

// A STALE dist is the likely failure here, not a missing one: the build happens
// on Windows and the measurement in WSL, so it is easy to edit footprint.ts and
// then measure with yesterday's dist. Destructuring an absent export yields
// `undefined` and fails much later with "x is not a function", by which point
// the message says nothing about the cause.
const REQUIRED = {
  '@vibeguard/rules': { getRule },
  'remediation-engine/fixers': { buildFix, applyFixes, fixers },
  'remediation-engine/footprint': {
    probeArmToolchain,
    parseSizeOutput,
    measureAll,
    renderFootprint,
    renderMarkdownTable,
    formatDelta,
  },
};
const missing = Object.entries(REQUIRED).flatMap(([mod, exports]) =>
  Object.entries(exports)
    .filter(([, v]) => v === undefined)
    .map(([name]) => `${mod}.${name}`),
);
if (missing.length) {
  process.stderr.write(
    [
      'the built dist is missing exports this script needs — it is out of date:',
      ...missing.map((m) => `  - ${m}`),
      '',
      'Rebuild on the Windows side (npm run build) and re-run.',
      '',
    ].join('\n'),
  );
  process.exit(2);
}

// >>> SPECIMENS BEGIN — everything between these markers is C source that gets
// compiled. Keep it free of anything whose value changes between builds (the
// predefined-macro check below, and a test in footprint.test.ts, both enforce
// that): a specimen that embeds the clock or its own path cannot be re-measured.
//
// Every specimen is a MINIMAL firmware fragment that makes its rule fire exactly
// once, and that compiles against newlib alone. "Exactly once" is not decoration:
// it means the after side is "every edit the fixer produced for every match the
// rule reported", with no selection step for anyone to argue about.

/** Specimens whose `after` is produced by the fixer itself. */
const FIXER_SPECIMENS = [
  {
    ruleId: 'VG-EMB-020',
    before: `// Telemetry loop, in the shape an LLM emits it: a debug flag defined in the
// source decides whether the debug print is compiled into the image.
#include <stdio.h>

#define DEBUG 1

unsigned g_tick_count;

void telemetry_tick(unsigned ticks, int rssi)
{
#if DEBUG
    printf("tick=%u rssi=%d\\n", ticks, rssi);
#endif
    g_tick_count = ticks;
}
`,
    note:
      'The flip drops a `#if DEBUG` block from the translation unit, so this is the row ' +
      'where a security fix is expected to REMOVE code rather than add it. The counter is ' +
      'in .bss on both sides, which makes the RAM column a control. Expected direction ' +
      'only — the measured number is what decides.',
  },
  {
    ruleId: 'VG-EMB-021',
    before: `// A test hook that shipped: a bypass define decides whether the real token
// comparison is compiled in at all.
#include <string.h>

#define BYPASS_AUTH 1

int session_open(const char *token, const char *expected)
{
#if BYPASS_AUTH
    (void)token;
    (void)expected;
    return 1;
#else
    return strcmp(token, expected) == 0;
#endif
}
`,
    note:
      'The mirror image of VG-EMB-020: turning the bypass off compiles the real comparison ' +
      'back in, so this is the row where the cost of a security fix, if there is one, shows ' +
      'up. It is the number the "we cannot afford the fix" objection is actually about — so ' +
      'it is the number, not the reasoning, that answers it.',
  },
  {
    ruleId: 'VG-EMB-010',
    before: `// Firmware posting telemetry to a fixed endpoint URL held in flash.
#include <stddef.h>

extern int http_post(const char *url, const void *body, size_t len);

static const char TELEMETRY_URL[] = "http://telemetry.example.com/v1/ingest";

int send_telemetry(const void *body, size_t len)
{
    return http_post(TELEMETRY_URL, body, len);
}
`,
    note:
      'The whole edit is one character of .rodata. The delta is the honest cost of the ' +
      'SCHEME change only; the TLS stack that has to exist for https to work is not in ' +
      'this translation unit and not in this number.',
  },
  {
    ruleId: 'VG-EMB-011',
    // The authmode constants belong to <mbedtls/ssl.h>, which is not part of a
    // bare-metal sysroot. Their upstream values are supplied with -D (below),
    // identically for both sides, rather than #define'd inside the specimen —
    // a definition line would itself be a match for this rule, so the specimen
    // would report two findings and the fixer would rewrite the definition as
    // well as the call site. Declaring the function is not stubbing it: nothing
    // links here (-c), so no body is invented.
    before: `// TLS brought up with an explicit authmode constant.
extern void mbedtls_ssl_conf_authmode(void *conf, int authmode);

void tls_setup(void *conf)
{
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
}
`,
    extraFlags: ['-DMBEDTLS_SSL_VERIFY_NONE=0', '-DMBEDTLS_SSL_VERIFY_REQUIRED=2'],
    note:
      'Values are upstream mbedtls/ssl.h (NONE 0, OPTIONAL 1, REQUIRED 2), passed with -D ' +
      'to both sides. `void *conf` stands in for `mbedtls_ssl_config *` — same code for the ' +
      'call. Whatever this row measures is the cost OF THE EDIT, and only that: the cost of ' +
      'actually verifying (a CA in flash) is not measured, because the fixer does not ' +
      'install a CA — it cannot know which one, and guessing is what fixers.ts forbids.',
  },
  {
    ruleId: 'VG-RTOS-004',
    before: `// NuttX-style log writer. O_DIRECT skips the page cache; whether the record is
// also forced out to storage before the next brown-out is decided by the flags.
#include <fcntl.h>
#include <unistd.h>

int log_flush(const char *path, const void *rec, unsigned n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_DIRECT, 0600);
    if (fd < 0) {
        return -1;
    }
    write(fd, rec, n);
    return close(fd);
}
`,
    note:
      'O_DIRECT and O_SYNC both come from newlib fcntl.h, so this specimen needs no extra ' +
      'flags. The edit widens one constant; any flash delta here is instruction encoding, ' +
      'not the durability cost (that is paid in wall-clock time on the device, which this ' +
      'script does not and cannot measure).',
  },
];

/**
 * Hand-written pairs. THESE ARE NOT FIXER OUTPUT and are rendered under their own
 * heading. They exist to show the cost of a fix VibeGuard deliberately does not
 * automate: both after sides invent a bound (32, 64) that the before side does
 * not contain, which is exactly the invention fixers.ts refuses to make.
 */
const ILLUSTRATIVE_PAIRS = [
  {
    ruleId: 'VG-MEM-002',
    label: 'strcpy → snprintf (hand-written)',
    before: `#include <string.h>

void copy_name(char *dst, const char *src)
{
    strcpy(dst, src);
}
`,
    after: `#include <stdio.h>

void copy_name(char *dst, const char *src)
{
    snprintf(dst, 32, "%s", src);
}
`,
    note:
      'The 32 is invented — nothing in the before side says how big dst is. That invention ' +
      'is why VG-MEM-002 has no fixer, and why this row is not in the measured table.',
  },
  {
    ruleId: 'VG-MEM-001',
    label: 'gets → fgets (hand-written)',
    before: `#include <stdio.h>

void read_line(char *buf)
{
    gets(buf);
}
`,
    after: `#include <stdio.h>

void read_line(char *buf)
{
    fgets(buf, 64, stdin);
}
`,
    note:
      'gets() was removed from C11; newlib still declares it, so the before side compiles ' +
      'here. The 64 is invented, same as above — the rule\'s own remediation says ' +
      'sizeof(buf), which a fixer cannot see from the call site.',
  },
];
// <<< SPECIMENS END

// A predefined macro whose value depends on WHEN or WHERE the compile happened
// lands in .rodata and moves the flash delta between two runs of the same
// specimen. Checked at run time here (so specimens added later are covered) and
// again as a text check in footprint.test.ts (so the check cannot be removed by
// deleting this call).
const BUILD_VARYING_MACROS = ['__FILE__', '__DATE__', '__TIME__', '__TIMESTAMP__', '__COUNTER__'];
function assertReproducible(id, side, source) {
  for (const macro of BUILD_VARYING_MACROS) {
    if (source.includes(macro)) {
      process.stderr.write(`specimen ${id} (${side}) contains ${macro}; it would not re-measure.\n`);
      process.exit(3);
    }
  }
}

// ── derive the after side from the real fixer ────────────────────────────────
/**
 * Run the actual rule and the actual fixer over a specimen. Returns the pair the
 * table layer measures, plus a human-readable trace of what happened.
 *
 * Every failure path here yields `after: null` with reason 'no-fix-produced'
 * rather than a hand-repaired after side: if the pipeline did not produce a
 * patch, there is no patch of ours to weigh, and saying so is the whole contract.
 */
function derivePair(spec) {
  const trace = { ruleId: spec.ruleId, matches: null, fix: null, problem: null };
  const rule = getRule(spec.ruleId);
  if (!rule) {
    trace.problem = `no such rule in the built engine`;
    return { pair: nullPair(spec, trace), trace };
  }
  if (!fixers[spec.ruleId]) {
    trace.problem = `rule has no fixer`;
    return { pair: nullPair(spec, trace), trace };
  }
  const matches = rule.match({
    filePath: `${spec.ruleId.toLowerCase()}.c`,
    language: 'c',
    content: spec.before,
    lines: spec.before.split('\n'),
  });
  trace.matches = matches.length;
  if (matches.length !== 1) {
    // Deliberately not "pick the first one": a specimen that fires twice is a
    // specimen whose measured delta depends on which match we chose, and that
    // choice would be invisible in the table.
    trace.problem = `specimen fires ${matches.length} times; it must fire exactly once`;
    return { pair: nullPair(spec, trace), trace };
  }
  const fix = buildFix(spec.ruleId, spec.before, matches[0]);
  if (!fix) {
    trace.problem = 'buildFix returned no edits for this match';
    return { pair: nullPair(spec, trace), trace };
  }
  trace.fix = { title: fix.title, safety: fix.safety, edits: fix.edits.length };
  const after = applyFixes(spec.before, fix.edits);
  if (after === null || after === spec.before) {
    trace.problem = after === null ? 'applyFixes refused (overlapping edits)' : 'fix was a no-op';
    return { pair: nullPair(spec, trace), trace };
  }
  return {
    pair: {
      id: spec.ruleId,
      label: `${fix.title} (${fix.safety})`,
      source: 'fixer-output',
      before: spec.before,
      after,
      extraFlags: spec.extraFlags,
      note: withFlags(spec),
    },
    trace,
  };
}

/**
 * Fold the per-specimen compiler flags into the note. The report's metadata block
 * can only show the flags every row shares; a reader who wants to reproduce ONE
 * row needs that row's own `-D`s, so they travel with the row.
 */
function withFlags(spec) {
  if (!spec.extraFlags?.length) return spec.note;
  return `${spec.note} Compiled (both sides) with: \`${spec.extraFlags.join(' ')}\`.`;
}

function nullPair(spec, trace) {
  return {
    id: spec.ruleId,
    label: `no fix produced — ${trace.problem}`,
    source: 'fixer-output',
    before: spec.before,
    after: null,
    whyNoAfter: 'no-fix-produced',
    extraFlags: spec.extraFlags,
    note: withFlags(spec),
  };
}

const derived = FIXER_SPECIMENS.map(derivePair);
const pairs = [
  ...derived.map((d) => d.pair),
  ...ILLUSTRATIVE_PAIRS.map((p) => ({
    id: p.ruleId,
    label: p.label,
    source: 'hand-written',
    before: p.before,
    after: p.after,
    note: p.note,
  })),
];
for (const p of pairs) {
  assertReproducible(p.id, 'before', p.before);
  if (p.after !== null) assertReproducible(p.id, 'after', p.after);
}

if (has('--print-specimens')) {
  for (const p of pairs) {
    process.stdout.write(`\n===== ${p.id} — ${p.label} [${p.source}] =====\n`);
    if (p.extraFlags?.length) process.stdout.write(`--- extra flags: ${p.extraFlags.join(' ')}\n`);
    process.stdout.write(`--- before ---\n${p.before}`);
    process.stdout.write(`--- after ---\n${p.after ?? '(none — nothing to compile)\n'}`);
  }
  process.exit(0);
}

// ── the instruments ──────────────────────────────────────────────────────────
const spawn = (cmd, args, opts) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', error: r.error };
};
const firstLine = (s) => (s ?? '').split('\n')[0]?.trim() || null;

/**
 * Compiler diagnostics, attributed per specimen so a warning cannot hide in the
 * noise. The attribution is by source text rather than by call order: order is
 * an assumption about how the engine walks the table, and an assumption that
 * silently mislabels which specimen warned is worse than no attribution.
 */
const diagnostics = [];
const idBySource = new Map();
for (const p of pairs) {
  idBySource.set(p.before, `${p.id} (before)`);
  if (p.after !== null) idBySource.set(p.after, `${p.id} (after)`);
}

function compileAndSize(source, extraFlags = []) {
  const currentId = idBySource.get(source) ?? '(unknown specimen)';
  // Compile with cwd INSIDE the temp dir and a relative file name, so the
  // invocation is byte-identical between runs (an absolute mkdtemp path would
  // otherwise reach the assembler's .file directive and the report's command
  // line, and differ every time).
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-'));
  try {
    writeFileSync(join(dir, 'u.c'), source, 'utf8');
    const gcc = spawn(GCC, [...BASE_CFLAGS, ...extraFlags, 'u.c', '-o', 'u.o'], { cwd: dir });
    if (gcc.stderr.trim()) diagnostics.push({ id: currentId, from: GCC, text: gcc.stderr.trim() });
    if (gcc.status !== 0) return null;
    const size = spawn(SIZE, ['u.o'], { cwd: dir });
    if (size.stderr.trim()) diagnostics.push({ id: currentId, from: SIZE, text: size.stderr.trim() });
    if (size.status !== 0) return null;
    return parseSizeOutput(size.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ONE probe for the whole run, reused for the rows AND for the metadata block
// below: the instrument named in the report is then necessarily the instrument
// that produced the numbers, not a second lookup that could disagree with it.
const probed = probeArmToolchain(spawn);
const probe = () => probed;

const rows = measureAll(pairs, { probe, compileAndSize });

// ── provenance of the numbers ────────────────────────────────────────────────
// Every field is captured from the machine that just ran, never hard-coded: the
// measuredWith string comes from the size binary's own --version, so a row cannot
// name an instrument that was not executed.
function osPrettyName() {
  try {
    const m = /^PRETTY_NAME="?([^"\n]{1,200})"?/m.exec(readFileSync('/etc/os-release', 'utf8'));
    return m?.[1] ?? null;
  } catch {
    return null;
  }
}
function dpkgVersions() {
  const r = spawn('dpkg-query', [
    '-W',
    '-f=${Package} ${Version}\n',
    'gcc-arm-none-eabi',
    'binutils-arm-none-eabi',
    'libnewlib-arm-none-eabi',
  ]);
  if (r.error || !r.stdout.trim()) return null;
  return r.stdout.trim().split('\n').map((l) => l.trim()).filter(Boolean);
}

const sizeVersion = probed.version;
const gccProbe = spawn(GCC, ['--version']);
const meta = {
  ranAt: new Date().toISOString(),
  host: `${process.platform} ${osRelease()} (node ${process.version})`,
  wslDistro: process.env.WSL_DISTRO_NAME ?? null,
  distro: osPrettyName(),
  sizeVersion,
  gccVersion: gccProbe.status === 0 ? firstLine(gccProbe.stdout) : null,
  packages: dpkgVersions(),
  compileCommand: `${GCC} ${BASE_CFLAGS.join(' ')} [<per-specimen -D flags>] u.c -o u.o`,
  sizeCommand: `${SIZE} u.o`,
};

// ── output ───────────────────────────────────────────────────────────────────
const metaLines = [
  ['run at', meta.ranAt],
  ['host', meta.host],
  ['WSL distro', meta.wslDistro ?? '(not WSL)'],
  ['distro', meta.distro ?? '(unknown)'],
  ['size', meta.sizeVersion ?? 'ABSENT — every row below is null'],
  ['gcc', meta.gccVersion ?? 'ABSENT — every row below is null'],
  ['packages', meta.packages ? meta.packages.join(', ') : '(dpkg-query unavailable)'],
  ['compile', meta.compileCommand],
  ['size cmd', meta.sizeCommand],
];

if (has('--markdown')) {
  const out = ['# VG-EMB 18b — embedded fix footprint', ''];
  out.push('| provenance | value |', '|---|---|');
  for (const [k, v] of metaLines) out.push(`| ${k} | \`${v}\` |`);
  out.push('');
  out.push(renderMarkdownTable(rows));
  if (diagnostics.length) {
    out.push('', '### Compiler diagnostics', '', '```');
    for (const d of diagnostics) out.push(`${d.id}: ${d.text}`);
    out.push('```');
  }
  out.push('');
  process.stdout.write(out.join('\n'));
} else {
  process.stdout.write('# VG-EMB 18b — embedded fix footprint\n\n');
  for (const [k, v] of metaLines) process.stdout.write(`  ${k.padEnd(11)} ${v}\n`);
  process.stdout.write('\n');
  for (const { pair, footprint } of rows) {
    const tag = pair.source === 'fixer-output' ? 'fixer output' : 'HAND-WRITTEN (not fixer output)';
    process.stdout.write(`  ${pair.id}  [${tag}]\n    ${pair.label}\n    ${renderFootprint(footprint)}\n`);
  }
  const derivedTrace = derived.filter((d) => d.trace.problem || d.trace.matches !== 1);
  if (derivedTrace.length) {
    process.stdout.write('\n  pipeline notes:\n');
    for (const d of derivedTrace) {
      process.stdout.write(`    ${d.trace.ruleId}: matches=${d.trace.matches} ${d.trace.problem ?? ''}\n`);
    }
  }
  if (diagnostics.length) {
    process.stdout.write('\n  compiler diagnostics:\n');
    for (const d of diagnostics) process.stdout.write(`    ${d.id}: ${d.text.replace(/\n/g, '\n      ')}\n`);
  }
  process.stdout.write('\n  Arduino-API fixes (WiFi/Serial) are absent by design: they need a board\n');
  process.stdout.write('  core to compile, and sizing a stub of ours would not be sizing the fix.\n');
}

const jsonPath = optValue('--json');
if (jsonPath) {
  writeFileSync(
    jsonPath,
    `${JSON.stringify(
      {
        tool: 'scripts/emb-fix-footprint.mjs',
        meta,
        rows: rows.map(({ pair, footprint }) => ({
          id: pair.id,
          label: pair.label,
          source: pair.source,
          extraFlags: pair.extraFlags ?? [],
          note: pair.note ?? null,
          flashDelta: footprint.flashDelta,
          ramDelta: footprint.ramDelta,
          flashRendered: formatDelta(footprint, footprint.flashDelta),
          ramRendered: formatDelta(footprint, footprint.ramDelta),
          measuredWith: footprint.measuredWith,
          reason: footprint.reason ?? null,
        })),
        pipeline: derived.map((d) => d.trace),
        diagnostics,
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
  process.stderr.write(`wrote ${jsonPath}\n`);
}

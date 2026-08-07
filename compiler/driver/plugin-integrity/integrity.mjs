// Plugin integrity check.
//
// Decides whether the plugins a compilation asked to load are ones the policy
// authorises, and records the pass pipeline that actually ran.
//
// Every non-obvious decision in here traces to a measurement in
// ~/vg-lab/plugin-integrity/probe.md. The four that shape the whole design:
//
//   * Loading is checked from the *command line*, not from whether clang
//     accepted the plugin. All three load spellings dlopen the object and run
//     its constructors, and -fpass-plugin= does so even on the path where it
//     then rejects the file as "entry point not found". By the time there is a
//     diagnostic, the code has run. (probe.md section 4b)
//
//   * -fpass-plugin= and -fplugin= are different slots. An LLVM pass plugin
//     handed to -fplugin= exits 0, prints nothing and does nothing, so a
//     checker that knows only one flag reports a clean build. (section 4)
//
//   * -mllvm -print-pipeline-passes works through the driver, but it
//     short-circuits codegen: the compiler exits 0 and writes a zero-byte
//     object. It can never be added to the build being checked. The pipeline
//     is captured by a separate shadow invocation with output forced to
//     /dev/null. (section 3)
//
//   * A plugin can be loaded with nothing in argv at all, via
//     CCC_OVERRIDE_OPTIONS. That is why this function takes env. (section 5b)
//
// The contract is compiler/schema/interfaces.md. In particular: an observation
// that could not be made is never reported as an observation that came back
// clean. `complete: false` is the only honest answer to "the pipeline could not
// be captured", and callers turn it into exit 3.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access, mkdir, writeFile } from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { execFile } from 'node:child_process';
import { basename, isAbsolute, relative, resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

const SEVERITY = {
  'VG-PLG-001': 'high',
  // A listed-by-nobody plugin ran inside the compiler. The schema is explicit
  // that this is a finding "whatever its digest".
  'VG-PLG-002': 'high',
  // Worse than 002: the policy vouches for this name, and the bytes behind the
  // name are not the bytes that were vouched for.
  'VG-PLG-003': 'critical',
  'VG-PLG-004': 'medium',
};

const TITLE = {
  'VG-PLG-001': 'A plugin was loaded that could not be resolved',
  'VG-PLG-002': 'A plugin was loaded that the policy does not list',
  'VG-PLG-003': 'A listed plugin was loaded with unexpected contents',
  'VG-PLG-004': 'The pass pipeline differs from the one the policy allows',
};

function finding(id, detail, where) {
  return {
    id,
    severity: SEVERITY[id],
    title: TITLE[id],
    detail,
    where: { kind: 'invocation', path: where.path ?? null, unit: null, pass: where.pass ?? null },
  };
}

// interfaces.md section 5: absolute paths must not appear in a record. Paths
// inside the working tree become relative; anything outside it is reduced to
// its basename, which is also the only part the policy matches on. The full
// path is deliberately dropped rather than emitted.
function recordPath(p, cwd) {
  if (p == null) return null;
  const abs = isAbsolute(p) ? p : resolve(cwd, p);
  const rel = relative(cwd, abs);
  if (rel && !rel.startsWith('..')) return rel.split('\\').join('/');
  return basename(abs);
}

// ---------------------------------------------------------------------------
// Command-line parsing
// ---------------------------------------------------------------------------

// Measured spellings (probe.md section 5). The space-separated form
// `-fpass-plugin PATH` is rejected by the driver as an unknown argument, so it
// is not accepted here either -- treating it as a load would invent a finding
// for a command line that cannot compile.
const PASS_PLUGIN_EQ = '-fpass-plugin=';
const FRONTEND_PLUGIN_EQ = '-fplugin=';

/**
 * Pull every plugin load out of a token list.
 * Returns [{ slot, spec, spelling, origin }].
 *   slot: 'pass' | 'frontend'  -- which policy list governs it
 */
function scanTokens(tokens, origin) {
  const loads = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    if (t.startsWith(PASS_PLUGIN_EQ)) {
      loads.push({ slot: 'pass', spec: t.slice(PASS_PLUGIN_EQ.length), spelling: PASS_PLUGIN_EQ, origin });
      continue;
    }
    // -fplugin-arg-<name>-<arg> is a sibling flag that carries no path; it must
    // not be mistaken for a load.
    if (t.startsWith(FRONTEND_PLUGIN_EQ)) {
      loads.push({ slot: 'frontend', spec: t.slice(FRONTEND_PLUGIN_EQ.length), spelling: FRONTEND_PLUGIN_EQ, origin });
      continue;
    }

    if (t === '-Xclang') {
      const next = tokens[i + 1];
      if (next == null) continue;

      // -Xclang -fpass-plugin=PATH : measured working, injects the pass.
      if (next.startsWith(PASS_PLUGIN_EQ)) {
        loads.push({ slot: 'pass', spec: next.slice(PASS_PLUGIN_EQ.length), spelling: '-Xclang ' + PASS_PLUGIN_EQ, origin });
        i++;
        continue;
      }
      if (next.startsWith(FRONTEND_PLUGIN_EQ)) {
        loads.push({ slot: 'frontend', spec: next.slice(FRONTEND_PLUGIN_EQ.length), spelling: '-Xclang ' + FRONTEND_PLUGIN_EQ, origin });
        i++;
        continue;
      }

      // -Xclang -load -Xclang PATH is the usual spelling; the cc1 flag takes
      // its value as a separate token, so the path may or may not carry its own
      // -Xclang. Both forms reach the same dlopen.
      if (next === '-load') {
        let j = i + 2;
        if (tokens[j] === '-Xclang') j++;
        if (tokens[j] != null) {
          loads.push({ slot: 'frontend', spec: tokens[j], spelling: '-Xclang -load', origin });
          i = j;
        }
        continue;
      }
      i++; // consumed an unrelated -Xclang payload
      continue;
    }

    // Bare cc1 spelling, for callers that pass a cc1 command line rather than a
    // driver one.
    if (t === '-load' && tokens[i + 1] != null) {
      loads.push({ slot: 'frontend', spec: tokens[i + 1], spelling: '-load', origin });
      i++;
    }
  }
  return loads;
}

// CCC_OVERRIDE_OPTIONS edits the driver's argument list from the environment
// (probe.md section 5b). '+X' appends, '^X' prepends. The editing operators
// 's/X/Y/', 'xX' and 'XX' rewrite or delete arguments, and what they produce
// cannot be known without replaying the driver's own edit -- so their presence
// makes the parse incomplete rather than clean.
function scanOverrideEnv(value) {
  const loads = [];
  let opaque = false;
  const tokens = String(value).trim().split(/\s+/).filter(Boolean);
  const plain = [];
  for (const tok of tokens) {
    if (tok === '#') { plain.length = 0; continue; }
    if (tok.startsWith('+') || tok.startsWith('^')) { plain.push(tok.slice(1)); continue; }
    if (tok.startsWith('s/') || tok.startsWith('x') || tok.startsWith('X')) { opaque = true; continue; }
    plain.push(tok);
  }
  loads.push(...scanTokens(plain, 'env:CCC_OVERRIDE_OPTIONS'));
  return { loads, opaque };
}

const SOURCE_RE = /\.(c|cc|cpp|cxx|c\+\+|m|mm|s|S)$/i;
function sourceInputs(argv) {
  const out = [];
  for (let i = 1; i < argv.length; i++) {
    const t = argv[i];
    if (t === '-o' || t === '-Xclang' || t === '-mllvm' || t === '-include') { i++; continue; }
    if (t.startsWith('-')) continue;
    if (SOURCE_RE.test(t)) out.push(t);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

async function sha256File(path) {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    const s = createReadStream(path);
    s.on('error', rej);
    s.on('data', (d) => h.update(d));
    s.on('end', () => res(h.digest('hex')));
  });
}

// ---------------------------------------------------------------------------
// Pipeline capture
// ---------------------------------------------------------------------------

// Split a printed pipeline into its top-level elements. Nesting matters:
// `function<eager-inv>(a,b)` is one element, and splitting naively on commas
// turns it into three that match nothing.
function splitPipeline(text) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of text.trim()) {
    if (ch === '(' || ch === '<') depth++;
    else if (ch === ')' || ch === '>') depth--;
    if (ch === ',' && depth === 0) { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function run(file, args, cwd) {
  return new Promise((res) => {
    execFile(file, args, { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 120000 },
      (err, stdout, stderr) => res({
        code: err && typeof err.code === 'number' ? err.code : (err ? -1 : 0),
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        failed: Boolean(err),
      }));
  });
}

// Build the shadow command line for ONE source file. Three edits, each of them
// load-bearing for a reason that was measured rather than assumed:
//
//   - every -o is dropped and replaced with /dev/null. The capture flag writes
//     a zero-byte object, so it must never be allowed to land on a real build
//     output. (probe.md section 3)
//
//   - the other source files are dropped, so exactly one TU is compiled. This
//     is not tidiness: `-c a.c b.c -o /dev/null` is rejected outright with
//     "cannot specify -o when generating multiple output files", and leaving
//     the -o off instead would write zero-byte a.o and b.o into the working
//     directory — destroying the very build outputs being checked. Compiling
//     one unit per shadow run avoids both, and is also the only way to attribute
//     a pipeline to a source file, since the pass-manager stream never names
//     one. (probe.md sections 2 and 3)
//
//   - -c is forced, so the shadow run stops before the link.
function shadowArgs(argv, keepSource, allSources) {
  const others = new Set(allSources.filter((s) => s !== keepSource));
  const out = [];
  for (let i = 1; i < argv.length; i++) {
    const t = argv[i];
    if (t === '-o') { i++; continue; }
    // The joined form (-ofoo.o) is valid and must be dropped too. `-O1` and
    // `-Os` are capital-O and are not affected; the only lowercase `-o…` flags
    // in clang are debug-info cosmetics whose absence cannot change which
    // passes run.
    if (t.startsWith('-o') && t.length > 2) continue;
    if (others.has(t)) continue;
    out.push(t);
  }
  if (!out.includes('-c')) out.push('-c');
  out.push('-mllvm', '-print-pipeline-passes', '-o', '/dev/null');
  return out;
}

async function capturePipeline({ argv, cwd }) {
  const unavailable = (reason) => ({
    available: false, method: null, reason,
    units: [], unitCount: 0, passes: [], raw: null,
  });

  const compiler = argv[0];
  if (!compiler) return unavailable('argv carried no compiler to invoke');

  const sources = sourceInputs(argv);
  if (sources.length === 0) {
    return unavailable('the invocation has no recognisable source input, so there is no pipeline to capture');
  }

  const units = [];
  const failures = [];
  for (const src of sources) {
    const r = await run(compiler, shadowArgs(argv, src, sources), cwd);
    const text = r.stdout.trim();
    if (r.failed || text === '') {
      failures.push(
        `${recordPath(src, cwd)} (exit ${r.code}` +
        `${r.stderr.trim() ? ': ' + r.stderr.trim().split('\n')[0] : ''})`,
      );
      continue;
    }
    // One complete pipeline per line; one source per shadow run, so one line.
    const line = text.split('\n').filter((l) => l.trim())[0];
    units.push({ source: recordPath(src, cwd), passes: splitPipeline(line), raw: line });
  }

  // Partial capture is not capture. If any unit could not be observed, the
  // result is incomplete even though other units succeeded — otherwise a build
  // where the interesting TU failed to probe reports the boring ones as clean.
  if (failures.length > 0) {
    const p = unavailable(
      `the shadow invocation produced no pipeline for ${failures.length} of ` +
      `${sources.length} source input(s): ${failures.join('; ')}`,
    );
    p.units = units;
    p.unitCount = units.length;
    return p;
  }

  return {
    available: true,
    method: 'print-pipeline-passes',
    reason: null,
    units,
    unitCount: units.length,
    // Convenience view of the first unit; `units` is the authoritative record.
    // Guarded rather than indexed blindly: an unresolvable plugin makes every
    // shadow run fail, and a checker that throws on the way to reporting that
    // is a checker that reports nothing at all.
    passes: units.length > 0 ? units[0].passes : [],
    raw: units.map((u) => `${u.source}\t${u.raw}`).join('\n'),
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * @param {object}   o
 * @param {object}   o.policy  parsed .vgpolicy.json (may be null/partial)
 * @param {string[]} o.argv    the full compiler command line; argv[0] is the compiler
 * @param {object}   o.env     environment the compiler would see
 * @param {string}   [o.labDir] where to drop raw capture artefacts; never under compiler/
 * @returns {Promise<{findings: object[], pipeline: object, complete: boolean}>}
 */
export async function checkPlugins({ policy, argv, env, labDir }) {
  const findings = [];
  let complete = true;

  const cwd = process.cwd();
  argv = Array.isArray(argv) ? argv.map(String) : [];
  env = env && typeof env === 'object' ? env : {};

  const where = { path: recordPath(sourceInputs(argv)[0] ?? null, cwd) };

  // -- 1. what did the command line ask to load? ----------------------------
  const loads = scanTokens(argv.slice(1), 'argv');
  if (typeof env.CCC_OVERRIDE_OPTIONS === 'string' && env.CCC_OVERRIDE_OPTIONS.trim()) {
    const { loads: envLoads, opaque } = scanOverrideEnv(env.CCC_OVERRIDE_OPTIONS);
    loads.push(...envLoads);
    if (opaque) {
      // The environment rewrites arguments in a way this parser does not
      // replay. Saying "no unauthorised plugin" here would be a guess.
      complete = false;
    }
  }

  const tc = (policy && policy.toolchain) || {};
  const allowLists = {
    pass: Array.isArray(tc.allowedPassPlugins) ? tc.allowedPassPlugins : [],
    frontend: Array.isArray(tc.allowedFrontendPlugins) ? tc.allowedFrontendPlugins : [],
  };

  // -- 2. resolve, digest, compare ------------------------------------------
  const manifest = [];
  for (const load of loads) {
    const abs = isAbsolute(load.spec) ? load.spec : resolve(cwd, load.spec);
    const name = basename(abs);
    const via = load.origin === 'argv' ? load.spelling : `${load.spelling} via ${load.origin}`;

    let digest = null;
    try {
      await access(abs, FS.R_OK);
      digest = await sha256File(abs);
    } catch {
      // The load was requested. Whether clang went on to accept it does not
      // change that the driver tried to dlopen it (probe.md section 4b), and it
      // does change what we can say about it: nothing.
      findings.push(finding('VG-PLG-001',
        `${name} was loaded with ${via} but could not be resolved or read, so its contents were not checked against the policy.`,
        where));
      complete = false;
      manifest.push({ name, slot: load.slot, origin: load.origin, sha256: null, verdict: 'unresolved' });
      continue;
    }

    const listed = allowLists[load.slot].filter((e) => e && e.name === name);
    if (listed.length === 0) {
      const listName = load.slot === 'pass' ? 'toolchain.allowedPassPlugins' : 'toolchain.allowedFrontendPlugins';
      findings.push(finding('VG-PLG-002',
        `${name} (sha256 ${digest}) was loaded with ${via} and is not in ${listName}.`,
        where));
      manifest.push({ name, slot: load.slot, origin: load.origin, sha256: digest, verdict: 'unlisted' });
      continue;
    }

    if (!listed.some((e) => e.sha256 === digest)) {
      const expected = listed.map((e) => e.sha256).join(' or ');
      findings.push(finding('VG-PLG-003',
        `${name} is listed in the policy, but the file loaded with ${via} has sha256 ${digest} where the policy pins ${expected}.`,
        where));
      manifest.push({ name, slot: load.slot, origin: load.origin, sha256: digest, verdict: 'digest-mismatch' });
      continue;
    }

    manifest.push({ name, slot: load.slot, origin: load.origin, sha256: digest, verdict: 'authorised' });
  }

  // -- 3. pipeline ----------------------------------------------------------
  const pipeline = await capturePipeline({ argv, cwd });
  if (!pipeline.available) {
    // interfaces.md section 7: "we did not look" is never reported as "clean".
    complete = false;
  }

  const allowed = tc.allowedPassPipeline;
  if (pipeline.available && Array.isArray(allowed)) {
    // Every unit is compared, and every difference is attributed to the source
    // file it was observed in. Comparing only the first unit would let a second
    // TU run anything it liked.
    for (const unit of pipeline.units) {
      const extra = unit.passes.filter((p) => !allowed.includes(p));
      const missing = allowed.filter((p) => !unit.passes.includes(p));
      for (const p of extra) {
        findings.push(finding('VG-PLG-004',
          `Compiling ${unit.source} ran ${p}, which toolchain.allowedPassPipeline does not list.`,
          { path: unit.source, pass: p }));
      }
      for (const p of missing) {
        findings.push(finding('VG-PLG-004',
          `toolchain.allowedPassPipeline lists ${p}, which compiling ${unit.source} did not run.`,
          { path: unit.source, pass: p }));
      }
    }
  } else if (!pipeline.available && Array.isArray(allowed)) {
    // A pipeline the policy constrains, that could not be observed, is the
    // exact case that must not come back as agreement.
    findings.push(finding('VG-PLG-004',
      `toolchain.allowedPassPipeline is set but the pipeline could not be captured: ${pipeline.reason}.`,
      where));
  }

  // -- 4. raw artefacts -----------------------------------------------------
  if (labDir) {
    try {
      await mkdir(labDir, { recursive: true });
      if (pipeline.raw != null) {
        await writeFile(resolve(labDir, 'pipeline.txt'), pipeline.raw + '\n', 'utf8');
      }
      await writeFile(resolve(labDir, 'plugins.json'),
        JSON.stringify({ plugins: manifest, pipelineAvailable: pipeline.available, complete }, null, 2) + '\n',
        'utf8');
    } catch {
      // Losing the artefact copy does not change the verdict, and must not be
      // allowed to turn a completed check into a failed one.
    }
  }

  return { findings, pipeline, complete };
}

export default { checkPlugins };
